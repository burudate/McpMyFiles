"""Run PowerShell snippets that emit JSON. Parameters are passed via environment variables (no string splicing)."""

from __future__ import annotations

import base64
import json
import os
import subprocess

_PRELUDE = "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n$ProgressPreference = 'SilentlyContinue'\n"


def run_json(script: str, env: dict[str, str] | None = None, timeout: float = 60) -> object:
    encoded = base64.b64encode((_PRELUDE + script).encode("utf-16-le")).decode("ascii")
    full_env = os.environ.copy()
    full_env.update(env or {})
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        # stdin must not be inherited: it is the MCP stdio channel.
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=full_env,
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    out = proc.stdout.decode("utf-8", errors="replace").lstrip("﻿").strip()
    if not out:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"PowerShell produced no output (exit {proc.returncode}): {err[:500]}")
    return json.loads(out)


PE_INFO_SCRIPT = r"""
$p = $env:MF_PATH
$r = [ordered]@{}
try {
  $v = (Get-Item -LiteralPath $p -Force).VersionInfo
  $r.company = $v.CompanyName; $r.product = $v.ProductName; $r.description = $v.FileDescription
  $r.original_filename = $v.OriginalFilename; $r.file_version = $v.FileVersion
} catch { $r.version_error = $_.Exception.Message }
try {
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $r.signature_status = [string]$s.Status
  if ($s.SignerCertificate) { $r.signer = $s.SignerCertificate.Subject }
} catch { $r.signature_error = $_.Exception.Message }
$r | ConvertTo-Json -Compress
"""


# Searches Sysmon (FileCreate=11, FileDelete=23/26) and Security (object access 4663/4656) logs.
EVENT_SEARCH_SCRIPT = r"""
$needle = $env:MF_NEEDLE
$start = (Get-Date).AddHours(-[double]$env:MF_HOURS)
$max = [int]$env:MF_MAX
$useSecurity = $env:MF_SECURITY -eq '1'
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'

function Get-EventData($evt) {
  $x = [xml]$evt.ToXml(); $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
  return $d
}

function Get-Status($err) {
  $id = [string]$err.FullyQualifiedErrorId
  if ($id -like 'NoMatchingEventsFound*') { return 'no_events' }
  if ($id -like 'NoMatchingLogsFound*') { return 'log_not_found' }
  if ($err.Exception -is [System.UnauthorizedAccessException] -or $err.Exception.Message -match 'unauthorized|access is denied|アクセスが拒否') { return 'access_denied' }
  return 'error: ' + $err.Exception.Message
}

$result = [ordered]@{
  sysmon   = [ordered]@{ status = 'ok'; events = @(); processes = @() }
  security = [ordered]@{ status = 'skipped'; events = @() }
}

$actions = @{ 11 = 'create'; 23 = 'delete (archived)'; 26 = 'delete' }
try {
  $events = Get-WinEvent -FilterHashtable @{ LogName = $sysmonLog; Id = 11, 23, 26; StartTime = $start } -ErrorAction Stop
  $found = New-Object System.Collections.ArrayList
  foreach ($e in $events) {
    if ($found.Count -ge $max) { break }
    $d = Get-EventData $e
    $t = $d['TargetFilename']
    if ($t -and $t.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
      [void]$found.Add([ordered]@{
        time = $e.TimeCreated.ToString('o'); action = $actions[[int]$e.Id]; target = $t
        image = $d['Image']; pid = $d['ProcessId']; user = $d['User']; process_guid = $d['ProcessGuid']
      })
    }
  }
  $result.sysmon.events = @($found)

  $guids = @($found | ForEach-Object { $_.process_guid } | Where-Object { $_ -match '^\{[0-9A-Fa-f-]{36}\}$' } | Select-Object -Unique -First 20)
  $procs = New-Object System.Collections.ArrayList
  foreach ($g in $guids) {
    $xp = "*[System[EventID=1] and EventData[Data[@Name='ProcessGuid']='$g']]"
    $pe = Get-WinEvent -LogName $sysmonLog -FilterXPath $xp -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($pe) {
      $d = Get-EventData $pe
      [void]$procs.Add([ordered]@{
        process_guid = $g; started = $pe.TimeCreated.ToString('o'); image = $d['Image']; command_line = $d['CommandLine']
        current_directory = $d['CurrentDirectory']; user = $d['User']; integrity = $d['IntegrityLevel']
        parent_image = $d['ParentImage']; parent_command_line = $d['ParentCommandLine']; parent_pid = $d['ParentProcessId']
      })
    }
  }
  $result.sysmon.processes = @($procs)
} catch { $result.sysmon.status = Get-Status $_ }

if ($useSecurity) {
  $result.security.status = 'ok'
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663, 4656; StartTime = $start } -MaxEvents 50000 -ErrorAction Stop
    $found = New-Object System.Collections.ArrayList
    foreach ($e in $events) {
      if ($found.Count -ge $max) { break }
      $d = Get-EventData $e
      $o = $d['ObjectName']
      if ($o -and $o.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $procId = $d['ProcessId']; if ($procId -like '0x*') { $procId = [string][Convert]::ToInt64($procId, 16) }
        [void]$found.Add([ordered]@{
          time = $e.TimeCreated.ToString('o'); event_id = $e.Id; target = $o; process = $d['ProcessName']; pid = $procId
          user = ($d['SubjectDomainName'] + '\' + $d['SubjectUserName']); access_mask = $d['AccessMask']
        })
      }
    }
    $result.security.events = @($found)
  } catch { $result.security.status = Get-Status $_ }
}

$result | ConvertTo-Json -Depth 6 -Compress
"""
