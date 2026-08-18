        # ---- issue and wait, a chunk at a time -------------------------
        #
        # Two passes. MTP failures are frequently transient - the provider is
        # busy, the handset is indexing, a thumbnail is being regenerated - and
        # a file that refused once will often come back on a second ask. One
        # retry costs seconds and converts a class of permanent gaps in the
        # exhibit into successful copies. Anything that fails twice is recorded
        # as a genuine failure with its reason.
        $attemptQueue = $queue
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            if ($attemptQueue.Count -eq 0) { break }
            if ($script:abortCopy) { break }
            if ($attempt -eq 2) {
                Write-Host ""
                Note ("Retrying {0} file(s) that did not arrive first time..." -f $attemptQueue.Count)
                Start-Sleep -Milliseconds 700   # let the provider settle
            }
            $nextQueue = New-Object System.Collections.ArrayList

            for ($start = 0; $start -lt $attemptQueue.Count; $start += $script:CHUNK) {
                if ($script:abortCopy) { break }

                $end = [Math]::Min($start + $script:CHUNK - 1, $attemptQueue.Count - 1)
                $slice = @($attemptQueue[$start..$end])

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

                    for ($k = 0; $k -lt $slice.Count; $k++) {
                        if ($done.ContainsKey($k)) { continue }
                        $f = $slice[$k]
                        $actual = Resolve-Arrived $f.Dir $f.Name
                        if (-not $actual) { continue }
                        $have = 0
                        try { $have = (Get-Item -LiteralPath $actual).Length } catch { continue }
                        $bytesNow += $have
                        if ($have -gt 0 -and ($f.Want -eq 0 -or $have -ge $f.Want)) {
                            $done[$k] = $true
                            $script:arrivedMap[$f.Rel] = $actual
                            $script:copied++
                            $prog.Items++; $prog.Bytes += $have
                            $progressed = $true
                        }
                    }

                    # Partial bytes count as progress: one large video can be
                    # many seconds from finishing while transferring perfectly.
                    if ($progressed -or $bytesNow -gt $lastBytes) {
                        $lastChange = Get-Date
                        $lastBytes = $bytesNow
                        $sleepMs = 20
                    } elseif ($sleepMs -lt 400) {
                        $sleepMs = [int]($sleepMs * 1.5) + 1
                    }

                    Write-Progress2 $prog

                    # Once anything in this batch has arrived the handset has
                    # proven it will serve, so a straggler gets a short grace
                    # rather than the full cold-start window.
                    $graceFor = if ($done.Count -gt 0) { $script:graceSeconds } else { $script:stallSeconds }
                    if (((Get-Date) - $lastChange).TotalSeconds -ge $graceFor) {
                        $stuck = @()
                        for ($k = 0; $k -lt $slice.Count; $k++) {
                            if (-not $done.ContainsKey($k)) { $stuck += $slice[$k] }
                        }
                        if ($stuck.Count -eq 0) { break }

                        if ($attempt -eq 1) {
                            # Hold them back for the retry pass rather than
                            # writing them off now.
                            foreach ($f in $stuck) { [void]$nextQueue.Add($f) }
                        } else {
                            $script:totalStalls++
                            Write-Host ""
                            Warn ("Gave up on {0} file(s) after two attempts:" -f $stuck.Count)
                            foreach ($f in ($stuck | Select-Object -First 4)) { Warn ("    {0}" -f $f.Rel) }
                            if ($stuck.Count -gt 4) { Dim ("    ... and {0} more" -f ($stuck.Count - 4)) }
                            Dim "Recorded in the manifest. The run continues."
                            Write-Host ""
                            foreach ($f in $stuck) {
                                [void]$script:failedFiles.Add(@{ path=$f.Rel
                                    reason="The handset listed this file but served no data for it across two attempts. Media providers routinely list entries they will not serve - trashed items and partially written files in particular." })
                                $prog.Items++
                            }
                        }
                        break
                    }
                }

                # ---- fail fast if the transfer is not working at all --------
                if ($prog.Bytes -le 0 -and $script:totalStalls -ge 2) {
                    $script:abortCopy = $true
                    Write-Host ""
                    Bad "STOPPING: not a single byte has transferred."
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

            $attemptQueue = $nextQueue
        }

        if ($script:abortCopy) { return }
