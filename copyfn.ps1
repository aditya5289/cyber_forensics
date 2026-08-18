    # ------------------------------------------------------------------
    # Copying, issued in bounded chunks.
    #
    # The previous version queued every file in a folder before waiting for
    # any of them. On a folder holding thousands of photographs that means
    # thousands of simultaneous asynchronous shell copies, and the shell does
    # not cope: nothing transfers, and the folder deadline - computed as four
    # seconds per pending file - then sat there for hours. Observed live at
    # 19 files and 0 bytes after eight minutes.
    #
    # So requests go out in chunks of 24. That is still pipelined, which is
    # the whole point of batching, but it is a queue depth the shell handles.
    #
    # Everything here is bounded. A chunk that stops making progress is
    # abandoned rather than waited out, because one file the media provider
    # will not serve must not hold up the other 23,000 - and the whole run
    # aborts early if nothing is transferring at all, instead of grinding for
    # hours to reach the same conclusion.
    # ------------------------------------------------------------------
    $script:CHUNK = 24
    $script:stallSeconds = 90
    $script:totalStalls = 0

    function Copy-Folder-Batch($folder, $prefix, $depth) {
        if ($depth -gt 12) { return }
        if ($script:abortCopy) { return }

        $subfolders = New-Object System.Collections.ArrayList
        $queue = New-Object System.Collections.ArrayList

        $destDir = if ($prefix) { Join-Path $Destination $prefix } else { $Destination }
        $destFolder = $null

        foreach ($item in $folder.Items()) {
            $rel = if ($prefix) { "$prefix\$($item.Name)" } else { $item.Name }
            if ($item.IsFolder) { [void]$subfolders.Add(@($item, $rel)); continue }

            $target = Join-Path $destDir $item.Name
            $want = 0
            if ($expected.ContainsKey($rel)) { $want = [int64]$expected[$rel] }

            # Resumable, but a zero-byte file is never accepted as finished.
            # Treating "size unknown, something exists" as complete would let
            # every empty placeholder left by an interrupted run count as a
            # successful copy.
            if (Test-Path -LiteralPath $target) {
                $existing = $null
                try { $existing = Get-Item -LiteralPath $target -Force -ErrorAction Stop } catch { }

                if ($null -ne $existing -and $existing.PSIsContainer) {
                    # MTP called this a file; the filesystem says folder. Never
                    # delete it - this is the path that once tried to remove a
                    # directory of already-acquired evidence.
                    $asFolder = $null
                    try { $asFolder = $item.GetFolder } catch { }
                    if ($null -ne $asFolder) { [void]$subfolders.Add(@($item, $rel)) }
                    else {
                        [void]$script:failedFiles.Add(@{ path=$rel
                            reason='Reported as a file by the handset, but a directory of that name exists at the destination. Left untouched.' })
                    }
                    continue
                }

                $have = 0
                if ($null -ne $existing) { try { $have = [int64]$existing.Length } catch { } }
                if ($have -gt 0 -and ($want -eq 0 -or $have -eq $want)) {
                    $script:skipped++
                    $prog.Items++; $prog.Bytes += $have
                    Write-Progress2 $prog
                    continue
                }
                Remove-Item -LiteralPath $target -Force -Confirm:$false -ErrorAction SilentlyContinue
            }

            [void]$queue.Add([PSCustomObject]@{ Item=$item; Rel=$rel; Target=$target; Want=$want })
        }

        # ---- issue and wait, a chunk at a time -------------------------
        for ($start = 0; $start -lt $queue.Count; $start += $script:CHUNK) {
            if ($script:abortCopy) { break }

            $end = [Math]::Min($start + $script:CHUNK - 1, $queue.Count - 1)
            $slice = @($queue[$start..$end])

            if (-not $destFolder) {
                $destFolder = Get-DestFolder $destDir
                if (-not $destFolder) {
                    foreach ($f in $slice) {
                        [void]$script:failedFiles.Add(@{ path=$f.Rel
                            reason='Destination folder could not be opened.' })
                    }
                    continue
                }
            }

            foreach ($f in $slice) {
                # 16 = yes to all, 512 = no progress dialog, 1024 = no error UI.
                $destFolder.CopyHere($f.Item, 16 -bor 512 -bor 1024)
            }

            $done = @{}
            $sleepMs = 20
            $lastChange = Get-Date
            $lastBytes = 0.0

            while ($done.Count -lt $slice.Count) {
                Start-Sleep -Milliseconds $sleepMs
                $bytesNow = 0.0
                $progressed = $false

                foreach ($f in $slice) {
                    if ($done.ContainsKey($f.Rel)) { continue }
                    if (-not (Test-Path -LiteralPath $f.Target)) { continue }
                    $have = 0
                    try { $have = (Get-Item -LiteralPath $f.Target).Length } catch { continue }
                    $bytesNow += $have
                    if ($have -gt 0 -and ($f.Want -eq 0 -or $have -ge $f.Want)) {
                        $done[$f.Rel] = $true
                        $script:copied++
                        $prog.Items++; $prog.Bytes += $have
                        $progressed = $true
                    }
                }

                # Partial bytes count as progress: a single large video can be
                # many seconds from completing while transferring perfectly.
                if ($progressed -or $bytesNow -gt $lastBytes) {
                    $lastChange = Get-Date
                    $lastBytes = $bytesNow
                    $sleepMs = 20
                } elseif ($sleepMs -lt 400) {
                    $sleepMs = [int]($sleepMs * 1.5) + 1
                }

                Write-Progress2 $prog

                if (((Get-Date) - $lastChange).TotalSeconds -ge $script:stallSeconds) {
                    $stuck = @($slice | Where-Object { -not $done.ContainsKey($_.Rel) })
                    $script:totalStalls++
                    Write-Host ""
                    Warn ("No data for {0}s - abandoning {1} file(s) in this batch:" -f
                          $script:stallSeconds, $stuck.Count)
                    foreach ($f in ($stuck | Select-Object -First 4)) {
                        Warn ("    {0}" -f $f.Rel)
                    }
                    if ($stuck.Count -gt 4) { Dim ("    ... and {0} more" -f ($stuck.Count - 4)) }
                    Dim "They are recorded in the manifest. The run continues."
                    Write-Host ""
                    foreach ($f in $stuck) {
                        [void]$script:failedFiles.Add(@{ path=$f.Rel
                            reason="The handset listed this file but served no data for it within $($script:stallSeconds)s. Media providers routinely list entries they will not serve." })
                        $prog.Items++
                    }
                    break
                }
            }

            # ---- fail fast if the transfer is not working at all --------
            if ($prog.Bytes -le 0 -and $script:totalStalls -ge 2) {
                $script:abortCopy = $true
                Write-Host ""
                Bad "STOPPING: not a single byte has transferred."
                Bad "$($script:totalStalls) batches timed out with nothing served."
                Write-Host ""
                Note "The handset is listing files but will not hand any over."
                Note "That is not a slow copy, and waiting will not fix it."
                Write-Host ""
                Note "In order of likelihood:"
                Note "  1. The phone locked. MTP stops serving on lock - unlock"
                Note "     it, keep the screen on, and run again to resume."
                Note "  2. USB mode reverted to charge-only. Re-select File"
                Note "     transfer on the notification."
                Note "  3. Replug, ideally into a rear USB 2.0 port, not a hub."
                Write-Host ""
                Note "Nothing acquired so far is lost - re-running resumes."
                break
            }
        }

        if ($script:abortCopy) { return }
        foreach ($sf in $subfolders) { Copy-Folder-Batch $sf[0].GetFolder $sf[1] ($depth + 1) }
    }
