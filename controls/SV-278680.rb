control 'SV-278680' do
  title 'Microsoft Defender AV must enable heuristics.'
  desc 'Always-on protection consists of real-time protection, behavior monitoring, and heuristics to identify malware based on known suspicious and malicious activities.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> Turn on heuristics is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

Criteria: If the value "DisableHeuristics" is REG_DWORD = 0, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> Turn on heuristics to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83214r1144082_chk'
  tag severity: 'medium'
  tag gid: 'V-278680'
  tag rid: 'SV-278680r1144083_rule'
  tag stig_id: 'WNDF-AV-000077'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-83119r1133731_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
