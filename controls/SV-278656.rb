control 'SV-278656' do
  title 'Microsoft Defender AV must configure local administrator merge behavior for lists.'
  desc 'This policy setting configures how locally defined lists are combined or merged with globally defined lists. This setting applies to exclusion lists, specified remediation lists, and attack surface reduction.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Configure local administrator merge behavior for lists is set to "Enabled". Otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender

Criteria: If the value "DisableLocalAdminMerge" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus  >> Configure local administrator merge behavior for lists to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83190r1144050_chk'
  tag severity: 'medium'
  tag gid: 'V-278656'
  tag rid: 'SV-278656r1144051_rule'
  tag stig_id: 'WNDF-AV-000052'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83095r1133659_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 0 => Passes
    # Value = 1 => FAILS
    its('DisableLocalAdminMerge') { should eq 1 }
  end

end
