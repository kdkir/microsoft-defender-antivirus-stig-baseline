control 'SV-278647' do
  title 'Microsoft Defender AV must block Adobe Reader from creating child processes.'
  desc 'This policy setting prevents Adobe Reader from launching other processes, which can help mitigate security risks associated with malicious PDF files.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" is REG_SZ = 1, this is not a finding.

If the value is other than 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" in the "Value Name" column.

Enter "1" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83181r1144029_chk'
  tag severity: 'medium'
  tag gid: 'V-278647'
  tag rid: 'SV-278647r1144030_rule'
  tag stig_id: 'WNDF-AV-000043'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83086r1134292_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules'

  describe registry_key(registry_path) do
    it { should exist }
    it { should have_property '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' }
    its('7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c') { should eq "1" }
  end

end
