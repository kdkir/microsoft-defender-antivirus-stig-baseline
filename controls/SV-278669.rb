control 'SV-278669' do
  title 'Microsoft Defender AV must enable real-time protection and Security Intelligence Updates during OOBE.'
  desc 'Always-on protection consists of real-time protection, behavior monitoring, and heuristics to identify malware based on known suspicious and malicious activities. These activities include events, such as processes making unusual changes to existing files, modifying or creating automatic startup registry keys and startup locations (also known as autostart extensibility points, or ASEPs), and other changes to the file system or file structure.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> Configure real-time protection and Security Intelligence Updates during OOBE is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "OobeEnableRtpAndSigUpdate" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> Configure real-time protection and Security Intelligence Updates during OOBE to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83203r1144064_chk'
  tag severity: 'medium'
  tag gid: 'V-278669'
  tag rid: 'SV-278669r1144065_rule'
  tag stig_id: 'WNDF-AV-000065'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-83108r1133698_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
