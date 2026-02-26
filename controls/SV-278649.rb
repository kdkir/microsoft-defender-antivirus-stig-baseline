control 'SV-278649' do
  title 'Microsoft Defender AV must block untrusted and unsigned processes that run from USB.'
  desc 'This policy setting helps prevents unsigned or untrusted executable files from running from USB removable drives, including SD cards. Blocked file types include executable files (such as .exe, .dll, or .scr).'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" is REG_SZ = 1, this is not a finding.

If the value is other than 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" in the "Value Name" column.

Enter "1" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83183r1144033_chk'
  tag severity: 'medium'
  tag gid: 'V-278649'
  tag rid: 'SV-278649r1144034_rule'
  tag stig_id: 'WNDF-AV-000045'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83088r1134296_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules'

  describe registry_key(registry_path) do
    it { should exist }
    it { should have_property 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' }
    its('b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4') { should eq "1" }
  end

end
