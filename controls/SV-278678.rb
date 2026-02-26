control 'SV-278678' do
  title 'Microsoft Defender AV must enable asynchronous inspection.'
  desc 'Network protection includes performance optimization that allows block mode to asynchronously inspect long-lived connections, which might provide a performance improvement. This optimization can also help with app compatibility problems.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Network Inspection System >> Turn on asynchronous inspection is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\NIS

Criteria: If the value "AllowSwitchToAsyncInspection" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MpEngine >> Turn on asynchronous inspection to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83212r1144078_chk'
  tag severity: 'medium'
  tag gid: 'V-278678'
  tag rid: 'SV-278678r1144079_rule'
  tag stig_id: 'WNDF-AV-000075'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83117r1133725_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\NIS'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 1 => Passes
    # Value = 0 => FAILS
    its('AllowSwitchToAsyncInspection') { should eq 1 }
  end
  
end
