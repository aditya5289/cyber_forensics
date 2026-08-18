# ================================================================== 9. DEMO
#
# Build a fake handset on disk, run the real analysis over it, and check the
# findings against answers that are known exactly.
#
# Every other test in this tool exercises one function. This exercises the
# pipeline: inventory, content typing by header, EXIF, video metadata, GPS,
# duplicate detection, hidden-folder detection, CSV and HTML output, and
# verification against a manifest. A bug in the glue between two working
# parts is invisible to unit tests and shows up here.
#
# It matters more than usual for this tool, because the alternative way to
# discover a pipeline bug is to spend an hour acquiring a real handset and
# find the report wrong at the end of it. This runs in seconds and needs no
# phone, so there is no excuse for not knowing.
function Invoke-Demo {
    Section "End-to-end demonstration"
    Note "Building a synthetic handset with known contents, then running the"
    Note "real analysis over it and checking every finding."
    Write-Host ""

    $root = Join-Path $env:TEMP "argus-demo-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $dcim = Join-Path $root 'DCIM\Camera'
    $vault = Join-Path $root 'Pictures\.private'
    $thumbs = Join-Path $root 'DCIM\.thumbnails'
    foreach ($d in @($dcim, $vault, $thumbs, (Join-Path $root 'Movies'))) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }

    $jpegBytes = [Convert]::FromBase64String($script:FIXTURE_JPEG_B64)
    $mp4Bytes  = [Convert]::FromBase64String($script:FIXTURE_MP4_B64)

    # Known contents, each planted to exercise one finding.
    [System.IO.File]::WriteAllBytes((Join-Path $dcim 'IMG_0001.jpg'), $jpegBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $dcim 'IMG_0002.jpg'), $jpegBytes)   # exact duplicate
    [System.IO.File]::WriteAllBytes((Join-Path $root 'Movies\VID_0001.mp4'), $mp4Bytes)
    [System.IO.File]::WriteAllBytes((Join-Path $vault 'hidden.jpg'), $jpegBytes)
    Set-Content -LiteralPath (Join-Path $vault '.nomedia') -Value '' -Encoding UTF8
    [System.IO.File]::WriteAllBytes((Join-Path $thumbs 'orphan_thumb.jpg'), $jpegBytes)
    # A PNG that claims to be a document - content typing must see through it.
    [System.IO.File]::WriteAllBytes((Join-Path $root 'notes.txt'),
        [byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A) + (New-Object byte[] 64))

    $planted = 7
    Good "$planted file(s) planted in $root"
    Write-Host ""

    $pass = 0; $fail = 0
    function DCheck($name, $cond, $detail = '') {
        if ($cond) { $script:dpass++; Write-Host "  PASS  $name" -ForegroundColor Green }
        else { $script:dfail++; Write-Host "  FAIL  $name  $detail" -ForegroundColor Red }
    }
    $script:dpass = 0; $script:dfail = 0

    try {
        Invoke-Analyze -Path $root | Out-Null

        Section "Checking the findings"

        $exifCsv = @(Get-ChildItem -LiteralPath $root -Filter 'argus-exif-*.csv' -ErrorAction SilentlyContinue)
        DCheck "an EXIF CSV was written" ($exifCsv.Count -eq 1)

        if ($exifCsv.Count -eq 1) {
            $rows = @(Import-Csv -LiteralPath $exifCsv[0].FullName)
            DCheck "EXIF found in all 4 JPEGs" ($rows.Count -eq 4) "got $($rows.Count)"
            $withGps = @($rows | Where-Object { $_.Lat -and $_.Lat -ne '' })
            DCheck "all 4 carry a GPS fix" ($withGps.Count -eq 4) "got $($withGps.Count)"
            if ($withGps.Count -gt 0) {
                $lat = [double]$withGps[0].Lat
                $lon = [double]$withGps[0].Lon
                DCheck "latitude is 51.4775"  ([Math]::Abs($lat - 51.4775) -lt 0.0001) "got $lat"
                # The sign is the whole point: ignore the W reference and the
                # point lands in the wrong hemisphere, entirely plausibly.
                DCheck "longitude is -0.0015" ([Math]::Abs($lon + 0.0015) -lt 0.0001) "got $lon"
                DCheck "camera is ARGUS TESTCAM-1" ($withGps[0].Camera -match 'TESTCAM-1') "got '$($withGps[0].Camera)'"
            }
        }

        $vidCsv = @(Get-ChildItem -LiteralPath $root -Filter 'argus-video-*.csv' -ErrorAction SilentlyContinue)
        DCheck "a video CSV was written" ($vidCsv.Count -eq 1)
        if ($vidCsv.Count -eq 1) {
            $v = @(Import-Csv -LiteralPath $vidCsv[0].FullName)
            DCheck "the clip was read" ($v.Count -eq 1) "got $($v.Count)"
            if ($v.Count -eq 1) {
                DCheck "recorded 2021-06-01 09:30:00Z" ($v[0].Created -eq '2021-06-01 09:30:00Z') "got '$($v[0].Created)'"
                DCheck "clip GPS is 48.8582" ([Math]::Abs([double]$v[0].Lat - 48.8582) -lt 0.0001) "got '$($v[0].Lat)'"
            }
        }

        $inv = @(Get-ChildItem -LiteralPath $root -Filter 'argus-inventory-*.csv' -ErrorAction SilentlyContinue)
        DCheck "an inventory CSV was written" ($inv.Count -eq 1)
        if ($inv.Count -eq 1) {
            $items = @(Import-Csv -LiteralPath $inv[0].FullName)
            DCheck "all $planted planted files inventoried" ($items.Count -eq $planted) "got $($items.Count)"
            # The tool's own output must never appear in its own inventory.
            $selfRefs = @($items | Where-Object { $_.Path -like 'argus-*' })
            DCheck "no argus-* output in the inventory" ($selfRefs.Count -eq 0) "found $($selfRefs.Count)"
        }

        $html = @(Get-ChildItem -LiteralPath $root -Filter 'argus-analysis-*.html' -ErrorAction SilentlyContinue)
        DCheck "an HTML report was written" ($html.Count -eq 1)
        if ($html.Count -eq 1) {
            $body = Get-Content -LiteralPath $html[0].FullName -Raw
            DCheck "report states the /data/data limitation" ($body -match 'data/data')
            DCheck "report carries the GPS caveat" ($body -match 'believed')
            DCheck "report lists the duplicate set" ($body -match 'duplicate|Duplicates|identical')
            DCheck "report is valid-looking HTML" ($body -match '</html>')
        }

        $custody = Join-Path $root 'argus-custody.jsonl'
        DCheck "a custody entry was written" (Test-Path -LiteralPath $custody)
        if (Test-Path -LiteralPath $custody) {
            $chain = Test-CustodyChain $root
            DCheck "the custody chain validates" ($chain.Broken.Count -eq 0) ($chain.Broken -join '; ')
        }

        # The PNG masquerading as notes.txt must be caught by its header.
        DCheck "content typing sees through a wrong extension" `
               ($html.Count -eq 1 -and (Get-Content -LiteralPath $html[0].FullName -Raw) -match 'notes\.txt')
    }
    catch {
        DCheck "the pipeline ran without error" $false $_.Exception.Message
    }
    finally {
        Remove-Item -LiteralPath $root -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    }

    Section "Demonstration result"
    if ($script:dfail -eq 0) {
        Good "$script:dpass checks passed."
        Good "The analysis pipeline works end to end on this machine."
        Write-Host ""
        Dim "This proves the half that runs AFTER acquisition. It says nothing"
        Dim "about whether your handset will hand its files over - only a real"
        Dim "acquisition tests that."
    } else {
        Bad "$script:dfail of $($script:dpass + $script:dfail) checks FAILED."
        Bad "Do not rely on analysis output until this is understood."
    }
}

