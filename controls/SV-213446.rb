control 'SV-213446' do
  title 'Microsoft Defender AV must be configured to enable behavior monitoring.'
  desc 'This policy setting allows configuration of behavior monitoring. If this setting is enabled or not configured, behavior monitoring will be enabled. If this setting is disabled, behavior monitoring will be disabled.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Turn on behavior monitoring" is set to "Enabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

If the value "DisableBehaviorMonitoring" is "REG_DWORD = 0", this is not a finding.
If the value does not exist, this is not a finding.
If the value is "1", this is a finding.

Alternate Check (if Microsoft Intune applied this setting):

Navigate to "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Policy Manager".

If the value "AllowBehaviorMonitoring" is "REG_DWORD = 1", this is not a finding.
If the value is "0", this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> Real-time Protection >> "Turn on behavior monitoring" to "Enabled " or "Not Configured".'
  impact 0.5
  tag check_id: 'C-14671r1260209_chk'
  tag severity: 'medium'
  tag gid: 'V-213446'
  tag rid: 'SV-213446r1260210_rule'
  tag stig_id: 'WNDF-AV-000022'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14669r820186_fix'
  tag 'documentable'
  tag legacy: ['SV-89909', 'V-75229']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  only_if('Windows Defender is not the active antivirus product') { windows_defender_active.active? }

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection'
  intune_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Policy Manager'

  # Alternate check applies when Microsoft Intune applied this setting instead of Group Policy
  if !registry_key(registry_path).has_property?('DisableBehaviorMonitoring') && registry_key(intune_path).has_property?('AllowBehaviorMonitoring')
    describe registry_key(intune_path) do
      its('AllowBehaviorMonitoring') { should eq 1 }
    end
  else
    describe registry_key(registry_path) do
      # Missing value => nil => passes
      # Value = 0 => Passes
      # Value = 1 => FAILS
      its('DisableBehaviorMonitoring') { should be_nil.or eq 0 }
    end
  end

end
