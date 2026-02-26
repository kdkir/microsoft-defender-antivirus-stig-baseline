control 'SV-278660' do
  title 'Microsoft Defender AV must hide the Family options area.'
  desc 'The Family options section contains links to settings and further information for parents of a Windows PC. It is not intended for enterprise or business environments.

This section can be hidden from users of the machine. This option can be useful if you do not want users in the organization to see or have access to this section.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Security >> Family Options >> Hide the Family options area is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Family options

Criteria: If the value "UILockdown" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Security >> Family Options >> Hide the Family options area to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83194r1144056_chk'
  tag severity: 'medium'
  tag gid: 'V-278660'
  tag rid: 'SV-278660r1144057_rule'
  tag stig_id: 'WNDF-AV-000056'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83099r1133671_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Family options'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 0 => Passes
    # Value = 1 => FAILS
    its('UILockdown') { should eq 1 }
  end

end
