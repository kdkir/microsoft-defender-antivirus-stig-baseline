control 'SV-278652' do
  title 'Microsoft Defender AV must block persistence through WMI event subscription.'
  desc 'This policy setting prevents malware from abusing WMI to attain persistence on a device.

Fileless threats employ various tactics to stay hidden, to avoid being seen in the file system, and to gain periodic execution control. Some threats can abuse the WMI repository and event model to stay hidden.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "e6db77e5-3df2-4cf1-b95a-636979351e5b" is REG_SZ = 2, this is not a finding.

If the value is other than 2, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "e6db77e5-3df2-4cf1-b95a-636979351e5b" in the "Value Name" column.

Enter "2" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83186r1144040_chk'
  tag severity: 'medium'
  tag gid: 'V-278652'
  tag rid: 'SV-278652r1144042_rule'
  tag stig_id: 'WNDF-AV-000048'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83091r1144041_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules'

  describe registry_key(registry_path) do
    it { should exist }
    it { should have_property 'e6db77e5-3df2-4cf1-b95a-636979351e5b' }
    its('e6db77e5-3df2-4cf1-b95a-636979351e5b') { should eq "2" }
  end

end
