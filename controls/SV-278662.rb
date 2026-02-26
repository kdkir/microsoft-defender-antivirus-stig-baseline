control 'SV-278662' do
  title 'Microsoft Defender AV must enable extended cloud check.'
  desc 'When Microsoft Defender Antivirus finds a suspicious file, it can prevent the file from running while it queries the Microsoft Defender Antivirus cloud service.

The default period that the file is blocked is 10 seconds. Extending the cloud block timeout period can help ensure there is enough time to receive a proper determination from the Microsoft Defender Antivirus cloud service.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MpEngine >> Configure extended cloud check is set to "Enabled" with a Policy Option value of "50"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine

Criteria: If the value "MpBafsExtendedTimeout" is REG_DWORD = 50, this is not a finding.

If the value is other than 50, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MpEngine >> Configure extended cloud check to "Enabled" with a Policy Option value of "50".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83196r1144060_chk'
  tag severity: 'medium'
  tag gid: 'V-278662'
  tag rid: 'SV-278662r1144061_rule'
  tag stig_id: 'WNDF-AV-000058'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83101r1133677_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 50 => Passes
    # Value = 1 => FAILS
    its('MpBafsExtendedTimeout') { should eq 50 }
  end

end
