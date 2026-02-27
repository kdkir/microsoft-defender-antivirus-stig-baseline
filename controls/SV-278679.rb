control 'SV-278679' do
  title 'Microsoft Defender AV must scan packed executables.'
  desc 'This policy setting manages whether Microsoft Defender Antivirus scans packed executables. Packed executables are executable files that contain compressed code.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> Scan packed executables is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

Criteria: If the value "DisablePackedExeScanning" is REG_DWORD = 0, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> Scan packed executables to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83213r1144080_chk'
  tag severity: 'medium'
  tag gid: 'V-278679'
  tag rid: 'SV-278679r1144081_rule'
  tag stig_id: 'WNDF-AV-000076'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-83118r1133728_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 0 => Passes
    # Value = 1 => FAILS
    its('DisablePackedExeScanning') { should be_nil.or eq 0 }
  end

end
