control 'SV-278653' do
  title 'Microsoft Defender AV must block executable files from running unless they meet a prevalence, age, or trusted list criterion.'
  desc 'This policy setting blocks executable files, such as .exe, .dll, or .scr, from launching. Thus, launching untrusted or unknown executable files can be risky, as it might not be initially clear if the files are malicious.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "01443614-cd74-433a-b99e-2ecdc07bfc25" is REG_SZ = 2, this is not a finding.

If the value is other than 2, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "01443614-cd74-433a-b99e-2ecdc07bfc25" in the "Value Name" column.

Enter "2" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83187r1144043_chk'
  tag severity: 'medium'
  tag gid: 'V-278653'
  tag rid: 'SV-278653r1144045_rule'
  tag stig_id: 'WNDF-AV-000049'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83092r1144044_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules'

  describe registry_key(registry_path) do
    it { should exist }
    it { should have_property '01443614-cd74-433a-b99e-2ecdc07bfc25' }
    its('01443614-cd74-433a-b99e-2ecdc07bfc25') { should eq "2" }
  end

end
