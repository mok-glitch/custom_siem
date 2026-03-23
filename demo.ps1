Write-Host "=== SIEM DEMO ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Dashboard is at: http://localhost:5000" -ForegroundColor Green
Write-Host "2. Login: admin / admin123" -ForegroundColor Green
Write-Host ""
Write-Host "Press Enter to generate attack..."
Read-Host

# Generate attack
python -c "import json; from datetime import datetime; f=open('Logs/auth.json','r'); a=json.load(f); f.close(); [a.insert(0,{'id':len(a)+i,'timestamp':datetime.now().isoformat(),'source_ip':'192.168.56.1','username':'admin','status':'Failure','logon_type':10,'process_name':'sshd.exe','failure_reason':'Bad password'}) for i in range(10)]; a.insert(0,{'id':len(a)+1,'timestamp':datetime.now().isoformat(),'source_ip':'192.168.56.1','username':'admin','status':'Success','logon_type':10,'process_name':'sshd.exe','failure_reason':''}); f=open('Logs/auth.json','w'); json.dump(a[:2000],f,indent=2); f.close(); print('✅ Attack generated!')"

Write-Host ""
Write-Host "Check Alerts page in 10 seconds!" -ForegroundColor Yellow