function Show-Gui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $selfPath = $PSCommandPath
    if (-not $selfPath) { $selfPath = $MyInvocation.MyCommand.Path }

    $sync = [hashtable]::Synchronized(@{
        Lines = New-Object System.Collections.ArrayList
        Busy  = $false
    })

    # ---- palette ---------------------------------------------------------
    $C = @{
        Bg      = [System.Drawing.Color]::FromArgb(13, 17, 23)
        Card    = [System.Drawing.Color]::FromArgb(22, 27, 34)
        Card2   = [System.Drawing.Color]::FromArgb(30, 36, 46)
        Line    = [System.Drawing.Color]::FromArgb(48, 54, 66)
        Text    = [System.Drawing.Color]::FromArgb(220, 224, 230)
        Muted   = [System.Drawing.Color]::FromArgb(125, 135, 150)
        Accent  = [System.Drawing.Color]::FromArgb(88, 166, 255)
        Good    = [System.Drawing.Color]::FromArgb(86, 211, 128)
        GoodDim = [System.Drawing.Color]::FromArgb(28, 58, 40)
        Warn    = [System.Drawing.Color]::FromArgb(226, 192, 109)
        Bad     = [System.Drawing.Color]::FromArgb(248, 113, 113)
        BadDim  = [System.Drawing.Color]::FromArgb(60, 30, 32)
    }
    $fontUi     = New-Object System.Drawing.Font('Segoe UI', 9)
    $fontTitle  = New-Object System.Drawing.Font('Segoe UI Semibold', 15, [System.Drawing.FontStyle]::Bold)
    $fontBig    = New-Object System.Drawing.Font('Segoe UI Semibold', 12, [System.Drawing.FontStyle]::Bold)
    $fontMedium = New-Object System.Drawing.Font('Segoe UI', 10)
    $fontSmall  = New-Object System.Drawing.Font('Segoe UI', 8.5)
    $fontMono   = New-Object System.Drawing.Font('Consolas', 9.5)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "ARGUS  -  mobile device acquisition"
    $form.Size = New-Object System.Drawing.Size(1100, 800)
    $form.MinimumSize = New-Object System.Drawing.Size(940, 640)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = $C.Bg
    $form.ForeColor = $C.Text
    $form.Font = $fontUi

    function New-Label($text, $x, $y, $font, $colour, $w = 0) {
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $text
        $l.Location = New-Object System.Drawing.Point($x, $y)
        $l.Font = $font
        $l.ForeColor = $colour
        $l.BackColor = [System.Drawing.Color]::Transparent
        if ($w -gt 0) { $l.Size = New-Object System.Drawing.Size($w, 20) } else { $l.AutoSize = $true }
        return $l
    }

    # ---- title -----------------------------------------------------------
    $form.Controls.Add((New-Label "ARGUS" 24 16 $fontTitle $C.Accent))
    $form.Controls.Add((New-Label "Mobile device acquisition and triage" 96 24 $fontMedium $C.Muted))
    $verLabel = New-Label "v$script:Version   $env:COMPUTERNAME\$env:USERNAME" 24 46 $fontSmall $C.Muted
    $form.Controls.Add($verLabel)

    # ---- device status card ---------------------------------------------
    # The window opens knowing what is attached. Making the operator press
    # "Scan" before the tool will say anything is a needless step in front of
    # the only question they actually have.
    $card = New-Object System.Windows.Forms.Panel
    $card.Location = New-Object System.Drawing.Point(24, 74)
    $card.Size = New-Object System.Drawing.Size(1040, 92)
    $card.BackColor = $C.Card
    $card.Anchor = 'Top,Left,Right'
    $form.Controls.Add($card)

    $dot = New-Object System.Windows.Forms.Panel
    $dot.Location = New-Object System.Drawing.Point(20, 34)
    $dot.Size = New-Object System.Drawing.Size(16, 16)
    $dot.BackColor = $C.Muted
    $card.Controls.Add($dot)

    $devTitle = New-Label "Looking for a handset..." 52 22 $fontBig $C.Text
    $card.Controls.Add($devTitle)
    $devSub = New-Label "" 54 50 $fontUi $C.Muted
    $card.Controls.Add($devSub)

    $refreshBtn = New-Object System.Windows.Forms.Button
    $refreshBtn.Text = 'Refresh'
    $refreshBtn.Size = New-Object System.Drawing.Size(90, 28)
    $refreshBtn.Location = New-Object System.Drawing.Point(930, 32)
    $refreshBtn.FlatStyle = 'Flat'
    $refreshBtn.FlatAppearance.BorderColor = $C.Line
    $refreshBtn.BackColor = $C.Card2
    $refreshBtn.ForeColor = $C.Text
    $refreshBtn.Anchor = 'Top,Right'
    $card.Controls.Add($refreshBtn)

    # ---- primary action --------------------------------------------------
    $goBtn = New-Object System.Windows.Forms.Button
    $goBtn.Text = "Plug in a handset to begin"
    $goBtn.Size = New-Object System.Drawing.Size(1040, 56)
    $goBtn.Location = New-Object System.Drawing.Point(24, 178)
    $goBtn.FlatStyle = 'Flat'
    $goBtn.FlatAppearance.BorderSize = 0
    $goBtn.BackColor = $C.Card2
    $goBtn.ForeColor = $C.Muted
    $goBtn.Font = $fontBig
    $goBtn.Enabled = $false
    $goBtn.Anchor = 'Top,Left,Right'
    $goBtn.Cursor = 'Hand'
    $form.Controls.Add($goBtn)

    $goHint = New-Label "" 26 240 $fontSmall $C.Muted 1030
    $form.Controls.Add($goHint)

    # ---- secondary actions, grouped by when you need them ----------------
    $groups = @(
        @{ Title = 'IF NOTHING IS DETECTED'; X = 24; Items = @(
            @{ Key='raw';   Text='Raw dump';    Tip='Everything Windows reports, completely unfiltered. Use this when a phone is plugged in but nothing sees it - it is the only way to tell "not attached" from "the scan missed it".' }
            @{ Key='watch'; Text='Watch for a phone'; Tip='Waits and reports the moment a handset enumerates and mounts. Start this, then plug the phone in.' }
            @{ Key='scan';  Text='Full scan';    Tip='Four independent enumerators, port topology, driver problems and connection stability.' }
        )}
        @{ Title = 'ACQUIRE'; X = 372; Items = @(
            @{ Key='acquire'; Text='Copy phone (MTP)'; Tip='Copy a mounted handset with hashes and a reconciled manifest. No USB debugging needed.' }
            @{ Key='pull';    Text='Pull over adb';    Tip='Logical acquisition over adb. Reaches more than MTP but needs USB debugging authorised.' }
            @{ Key='history'; Text='Attachment history'; Tip='Handsets ever connected to this workstation, with first and last seen times.' }
        )}
        @{ Title = 'EXAMINE'; X = 720; Items = @(
            @{ Key='analyze'; Text='Analyse a folder'; Tip='Inventory, EXIF, GPS, video metadata, duplicates, and an HTML report.' }
            @{ Key='verify';  Text='Verify an exhibit'; Tip='Re-hash against the manifest and check the custody chain.' }
            @{ Key='triage';  Text='Triage a file';     Tip='Identify an opaque container and say whether it can be read.' }
        )}
    )

    $buttons = @{}
    $tip = New-Object System.Windows.Forms.ToolTip
    $tip.AutoPopDelay = 20000
    $tip.InitialDelay = 350
    foreach ($g in $groups) {
        $form.Controls.Add((New-Label $g.Title $g.X 276 $fontSmall $C.Muted))
        $y = 300
        foreach ($item in $g.Items) {
            $b = New-Object System.Windows.Forms.Button
            $b.Text = "   " + $item.Text
            $b.Size = New-Object System.Drawing.Size(324, 34)
            $b.Location = New-Object System.Drawing.Point($g.X, $y)
            $b.FlatStyle = 'Flat'
            $b.FlatAppearance.BorderColor = $C.Line
            $b.BackColor = $C.Card
            $b.ForeColor = $C.Text
            $b.TextAlign = 'MiddleLeft'
            $b.Cursor = 'Hand'
            $tip.SetToolTip($b, $item.Tip)
            $form.Controls.Add($b)
            $buttons[$item.Key] = $b
            $y += 40
        }
    }

    # Tools row
    $form.Controls.Add((New-Label 'TOOLS' 24 424 $fontSmall $C.Muted))
    $tx = 24
    foreach ($item in @(
        @{ Key='selftest'; Text='Self-test'; Tip='Known-answer tests against embedded fixtures. Run this before using the tool on evidence.' }
        @{ Key='doctor';   Text='Doctor';    Tip='Python, adb, and every ARGUS copy found on this machine.' })) {
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $item.Text
        $b.Size = New-Object System.Drawing.Size(158, 30)
        $b.Location = New-Object System.Drawing.Point($tx, 446)
        $b.FlatStyle = 'Flat'
        $b.FlatAppearance.BorderColor = $C.Line
        $b.BackColor = $C.Card
        $b.ForeColor = $C.Muted
        $b.Cursor = 'Hand'
        $tip.SetToolTip($b, $item.Tip)
        $form.Controls.Add($b)
        $buttons[$item.Key] = $b
        $tx += 166
    }

    # Hover feedback. Without it a flat button looks like a label and people
    # do not realise it can be pressed.
    foreach ($b in @($buttons.Values) + @($refreshBtn)) {
        $b.Add_MouseEnter({ $this.BackColor = $C.Card2 }.GetNewClosure())
        $b.Add_MouseLeave({ $this.BackColor = $C.Card }.GetNewClosure())
    }
    $goBtn.Add_MouseEnter({ if ($this.Enabled) { $this.BackColor = [System.Drawing.Color]::FromArgb(45, 105, 190) } })
    $goBtn.Add_MouseLeave({ if ($this.Enabled) { $this.BackColor = [System.Drawing.Color]::FromArgb(31, 92, 176) } })

    # ---- progress --------------------------------------------------------
    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Location = New-Object System.Drawing.Point(24, 492)
    $bar.Size = New-Object System.Drawing.Size(1040, 8)
    $bar.Style = 'Continuous'
    $bar.Anchor = 'Top,Left,Right'
    $bar.Visible = $false
    $form.Controls.Add($bar)

    # ---- output ----------------------------------------------------------
    $out = New-Object System.Windows.Forms.RichTextBox
    $out.Location = New-Object System.Drawing.Point(24, 512)
    $out.Size = New-Object System.Drawing.Size(1040, 200)
    $out.BackColor = [System.Drawing.Color]::FromArgb(9, 12, 16)
    $out.ForeColor = $C.Text
    $out.Font = $fontMono
    $out.ReadOnly = $true
    $out.DetectUrls = $false
    $out.BorderStyle = 'None'
    $out.Anchor = 'Top,Bottom,Left,Right'
    $form.Controls.Add($out)

    $statusLabel = New-Label "Ready." 24 724 $fontUi $C.Muted 700
    $statusLabel.Anchor = 'Bottom,Left'
    $form.Controls.Add($statusLabel)

    $saveBtn = New-Object System.Windows.Forms.Button
    $saveBtn.Text = 'Save log'
    $saveBtn.Size = New-Object System.Drawing.Size(96, 28)
    $saveBtn.Location = New-Object System.Drawing.Point(872, 720)
    $saveBtn.FlatStyle = 'Flat'
    $saveBtn.FlatAppearance.BorderColor = $C.Line
    $saveBtn.BackColor = $C.Card
    $saveBtn.ForeColor = $C.Text
    $saveBtn.Anchor = 'Bottom,Right'
    $form.Controls.Add($saveBtn)

    $clearBtn = New-Object System.Windows.Forms.Button
    $clearBtn.Text = 'Clear'
    $clearBtn.Size = New-Object System.Drawing.Size(80, 28)
    $clearBtn.Location = New-Object System.Drawing.Point(976, 720)
    $clearBtn.FlatStyle = 'Flat'
    $clearBtn.FlatAppearance.BorderColor = $C.Line
    $clearBtn.BackColor = $C.Card
    $clearBtn.ForeColor = $C.Text
    $clearBtn.Anchor = 'Bottom,Right'
    $form.Controls.Add($clearBtn)

    $colourMap = @{
        'Plain' = $C.Text;  'Green' = $C.Good;  'Yellow' = $C.Warn
        'Red'   = $C.Bad;   'Cyan'  = $C.Accent
        'DarkGray' = $C.Muted
        'Magenta'  = [System.Drawing.Color]::FromArgb(198, 149, 240)
        'White'    = [System.Drawing.Color]::White
        'DarkCyan' = [System.Drawing.Color]::FromArgb(80, 140, 200)
    }

    function Append-Line($text, $colour) {
        $c = $colourMap[$colour]
        if (-not $c) { $c = $C.Text }
        $out.SelectionStart = $out.TextLength
        $out.SelectionLength = 0
        $out.SelectionColor = $c
        $out.AppendText("$text`r`n")
        $out.SelectionStart = $out.TextLength
        $out.ScrollToCaret()

        # The engine already prints a percentage in its progress lines, so the
        # bar is driven by reading those rather than by a second progress
        # channel that could disagree with what the log says.
        if ($text -match '\]\s+(\d+)%') {
            $p = [int]$Matches[1]
            if ($p -ge 0 -and $p -le 100) {
                $bar.Visible = $true
                $bar.Value = $p
            }
        }
        if ($text -match 'left ~([^ ]+(?: [^ ]+)?)\s+done ~(\d\d:\d\d)') {
            $statusLabel.Text = "Working - about $($Matches[1]) remaining, finishing around $($Matches[2])"
        }
    }

    # ---- device polling --------------------------------------------------
    $script:currentDevice = ''

    function Update-DeviceCard {
        if ($sync.Busy) { return }
        try {
            $h = Get-MountedHandsets
            $names = @()
            if ($h.Ok) { $names = @($h.Items | ForEach-Object { $_.Name }) }

            $adbReady = @()
            $adbPath = Find-Tool 'adb'
            if ($adbPath) {
                foreach ($l in (& $adbPath devices 2>&1 | Select-Object -Skip 1)) {
                    if ($l -match '^(\S+)\s+device\s*$') { $adbReady += $Matches[1] }
                }
            }

            if ($names.Count -gt 0) {
                $script:currentDevice = $names[0]
                $dot.BackColor = $C.Good
                $devTitle.Text = $names[0]
                $devTitle.ForeColor = $C.Good
                $extra = if ($names.Count -gt 1) { "  (+$($names.Count - 1) more)" } else { '' }
                $devSub.Text = "Mounted and ready to copy - no USB debugging needed$extra"
                $goBtn.Text = "Acquire and analyse  $($names[0])"
                $goBtn.Enabled = $true
                $goBtn.BackColor = [System.Drawing.Color]::FromArgb(31, 92, 176)
                $goBtn.ForeColor = [System.Drawing.Color]::White
                $goHint.Text = "Copies shared storage, hashes every file, analyses it and writes a report. Typically 20-60 minutes."
            }
            elseif ($adbReady.Count -gt 0) {
                $script:currentDevice = $adbReady[0]
                $dot.BackColor = $C.Good
                $devTitle.Text = "$($adbReady[0])  (adb)"
                $devTitle.ForeColor = $C.Good
                $devSub.Text = "Authorised for adb. Reaches more than MTP, but not /data/data without root."
                $goBtn.Text = "Pull and analyse  $($adbReady[0])"
                $goBtn.Enabled = $true
                $goBtn.BackColor = [System.Drawing.Color]::FromArgb(31, 92, 176)
                $goBtn.ForeColor = [System.Drawing.Color]::White
                $goHint.Text = "Logical acquisition over adb, hashed and reconciled the same way."
            }
            else {
                $script:currentDevice = ''
                $dot.BackColor = $C.Muted
                $devTitle.Text = "No handset detected"
                $devTitle.ForeColor = $C.Muted
                $devSub.Text = "Plug the phone in, unlock it, and choose File transfer on the USB notification."
                $goBtn.Text = "Plug in a handset to begin"
                $goBtn.Enabled = $false
                $goBtn.BackColor = $C.Card2
                $goBtn.ForeColor = $C.Muted
                $goHint.Text = "If it IS connected and still not shown, press Raw dump - that reports everything Windows sees, with no filtering."
            }
        } catch {
            $dot.BackColor = $C.Warn
            $devTitle.Text = "Could not check for handsets"
            $devTitle.ForeColor = $C.Warn
            $devSub.Text = $_.Exception.Message
        }
    }

    # ---- background work -------------------------------------------------
    $script:runspace = $null
    $script:psinst = $null
    $script:handle = $null

    function Start-Work([string]$command, [string]$label) {
        if ($sync.Busy) {
            [System.Windows.Forms.MessageBox]::Show(
                "Something is already running.`n`nWait for it to finish. Stopping an " +
                "acquisition part-way leaves a partial copy that looks complete on disk.",
                "ARGUS", 'OK', 'Warning') | Out-Null
            return
        }
        $sync.Busy = $true
        foreach ($b in $buttons.Values) { $b.Enabled = $false }
        $goBtn.Enabled = $false
        $refreshBtn.Enabled = $false
        $bar.Visible = $true
        $bar.Value = 0
        $statusLabel.Text = "$label - running..."
        $statusLabel.ForeColor = $C.Accent

        $script:runspace = [runspacefactory]::CreateRunspace()
        $script:runspace.ApartmentState = 'STA'
        $script:runspace.Open()
        $script:runspace.SessionStateProxy.SetVariable('SYNC', $sync)
        $script:runspace.SessionStateProxy.SetVariable('SELF', $selfPath)
        $script:runspace.SessionStateProxy.SetVariable('CMD', $command)

        $script:psinst = [powershell]::Create()
        $script:psinst.Runspace = $script:runspace
        [void]$script:psinst.AddScript({
            try {
                . $SELF -NoEntry
                $script:GuiSink = $SYNC
                Invoke-Expression $CMD
            } catch {
                [void]$SYNC.Lines.Add([PSCustomObject]@{
                    Text = "  ERROR: $($_.Exception.Message)"; Colour = 'Red' })
                [void]$SYNC.Lines.Add([PSCustomObject]@{
                    Text = "  at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())"
                    Colour = 'DarkGray' })
            } finally {
                $SYNC.Busy = $false
            }
        })
        $script:handle = $script:psinst.BeginInvoke()
    }

    # A timer drains the queue on the UI thread; touching controls from the
    # worker runspace would be a cross-thread call and throw.
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 120
    $timer.Add_Tick({
        $n = 0
        while ($sync.Lines.Count -gt 0 -and $n -lt 200) {
            $item = $sync.Lines[0]
            $sync.Lines.RemoveAt(0)
            Append-Line $item.Text $item.Colour
            $n++
        }
        if (-not $sync.Busy -and $script:handle -and $script:handle.IsCompleted) {
            foreach ($b in $buttons.Values) { $b.Enabled = $true }
            $refreshBtn.Enabled = $true
            $bar.Visible = $false
            $statusLabel.Text = "Finished."
            $statusLabel.ForeColor = $C.Good
            try { $script:psinst.Dispose(); $script:runspace.Close() } catch {}
            $script:handle = $null
            Update-DeviceCard
        }
    })
    $timer.Start()

    $devTimer = New-Object System.Windows.Forms.Timer
    $devTimer.Interval = 4000
    $devTimer.Add_Tick({ Update-DeviceCard })
    $devTimer.Start()

    # ---- helpers ---------------------------------------------------------
    function Pick-Folder($prompt) {
        $d = New-Object System.Windows.Forms.FolderBrowserDialog
        $d.Description = $prompt
        if ($d.ShowDialog() -eq 'OK') { return $d.SelectedPath }
        return $null
    }
    function Pick-File($prompt) {
        $d = New-Object System.Windows.Forms.OpenFileDialog
        $d.Title = $prompt
        $d.Filter = 'All files (*.*)|*.*'
        if ($d.ShowDialog() -eq 'OK') { return $d.FileName }
        return $null
    }
    function Esc-Path($p) { $p -replace "'", "''" }

    # ---- wiring ----------------------------------------------------------
    $refreshBtn.Add_Click({ Update-DeviceCard })
    $buttons['raw'].Add_Click({ Start-Work 'Invoke-RawDump' 'Raw dump' })
    $buttons['scan'].Add_Click({ Start-Work 'Invoke-Scan | Out-Null' 'Scan' })
    $buttons['watch'].Add_Click({ Start-Work 'Invoke-Watch -Seconds 120' 'Watching' })
    $buttons['selftest'].Add_Click({ Start-Work 'Invoke-SelfTest' 'Self-test' })
    $buttons['doctor'].Add_Click({ Start-Work 'Invoke-Doctor' 'Doctor' })

    $goBtn.Add_Click({
        if (-not $script:currentDevice) { Update-DeviceCard; return }
        $name = $script:currentDevice
        $slug = ($name -replace '[^A-Za-z0-9]', '-').ToLower().Trim('-')
        $dest = "C:\evidence\$slug-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Acquire '$name' and run the full sequence?" + [char]10 + [char]10 +
            "Into:  $dest" + [char]10 + [char]10 +
            "1. Copy shared storage, hashing every file" + [char]10 +
            "2. Analyse - EXIF, GPS, video metadata, duplicates" + [char]10 +
            "3. Verify against the manifest" + [char]10 +
            "4. Open an HTML report" + [char]10 + [char]10 +
            "Commonly 20-60 minutes. Leave the phone unlocked and plugged in. " +
            "Progress and a finish time appear below as it runs.",
            "ARGUS - acquire and analyse", 'OKCancel', 'Question')
        if ($r -ne 'OK') { return }
        Start-Work "Invoke-Auto -DeviceName '$(Esc-Path $name)' -Destination '$(Esc-Path $dest)' -Yes" `
                   "Acquiring $name"
    })

    $buttons['acquire'].Add_Click({
        if (-not $script:currentDevice) {
            [System.Windows.Forms.MessageBox]::Show(
                "No handset is mounted." + [char]10 + [char]10 +
                "On the phone: pull down the notification shade, tap the USB " +
                "notification, and choose File transfer.", "ARGUS", 'OK', 'Information') | Out-Null
            return
        }
        $dest = Pick-Folder "Choose an EMPTY folder for the acquisition"
        if (-not $dest) { return }
        Start-Work "Invoke-Acquire -DeviceName '$(Esc-Path $script:currentDevice)' -Destination '$(Esc-Path $dest)'" `
                   "Copying $script:currentDevice"
    })

    $buttons['pull'].Add_Click({
        $dest = Pick-Folder "Choose a folder for the adb acquisition"
        if (-not $dest) { return }
        Start-Work "Invoke-Pull -Destination '$(Esc-Path $dest)'" 'adb pull'
    })

    $buttons['analyze'].Add_Click({
        $p = Pick-Folder "Which acquisition folder should be analysed?"
        if (-not $p) { return }
        Start-Work "Invoke-Analyze -Path '$(Esc-Path $p)'" 'Analysing'
    })

    $buttons['verify'].Add_Click({
        $p = Pick-Folder "Which acquisition folder should be verified?"
        if (-not $p) { return }
        Start-Work "Invoke-Verify -Path '$(Esc-Path $p)'" 'Verifying'
    })

    $buttons['triage'].Add_Click({
        $p = Pick-File "Which container file should be triaged?"
        if (-not $p) { return }
        Start-Work "Invoke-Triage -Path '$(Esc-Path $p)'" 'Triage'
    })

    $buttons['history'].Add_Click({
        Start-Work @'
Section "Handsets ever attached to this workstation"
$h = Get-UsbHistory -HandsetsOnly
if (-not $h.Ok) { Bad "Could not read the USB history: $($h.Error)" }
elseif ($h.Devices.Count -eq 0) { Note "None recorded." }
else {
  foreach ($d in ($h.Devices | Sort-Object { $_.LastArrival } -Descending)) {
    Write-Host ("  {0,-22} {1}:{2}  {3}" -f $d.Vendor,$d.Vid,$d.Pid,$d.Name) -ForegroundColor Green
    if ($d.Serial)      { Dim "      serial:       $($d.Serial)" }
    if ($d.FirstSeen)   { Dim ("      first seen:   {0:yyyy-MM-dd HH:mm} UTC" -f $d.FirstSeen) }
    if ($d.LastArrival) { Dim ("      last arrival: {0:yyyy-MM-dd HH:mm} UTC" -f $d.LastArrival) }
  }
  Write-Host ""
  Dim "From Windows' own device registry - this workstation, not any handset."
}
'@ 'Attachment history'
    })

    $saveBtn.Add_Click({
        $d = New-Object System.Windows.Forms.SaveFileDialog
        $d.Filter = 'Text (*.txt)|*.txt'
        $d.FileName = "argus-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
        if ($d.ShowDialog() -eq 'OK') {
            $out.Text | Set-Content -LiteralPath $d.FileName -Encoding UTF8
            $statusLabel.Text = "Log saved to $($d.FileName)"
        }
    })
    $clearBtn.Add_Click({ $out.Clear() })

    $form.Add_FormClosing({
        if ($sync.Busy) {
            $r = [System.Windows.Forms.MessageBox]::Show(
                "Work is still running." + [char]10 + [char]10 +
                "Closing now leaves a partial acquisition with no manifest, " +
                "which on disk is indistinguishable from a complete one." + [char]10 + [char]10 +
                "Close anyway?", "ARGUS", 'YesNo', 'Warning')
            if ($r -ne 'Yes') { $_.Cancel = $true; return }
        }
        $timer.Stop(); $devTimer.Stop()
        try { if ($script:psinst) { $script:psinst.Dispose() } } catch {}
        try { if ($script:runspace) { $script:runspace.Close() } } catch {}
    })

    Append-Line "" 'Plain'
    Append-Line "  ARGUS $script:Version - nothing is installed, nothing leaves this machine." 'DarkGray'
    Append-Line "  Suggested first run: Self-test, then plug the phone in." 'DarkGray'
    Append-Line "" 'Plain'

    Update-DeviceCard
    [void]$form.ShowDialog()
}

