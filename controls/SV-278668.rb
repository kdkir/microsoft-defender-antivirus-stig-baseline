control 'SV-278668' do
  title 'Microsoft Defender AV must enable script scanning.'
  desc 'Always-on protection consists of real-time protection, behavior monitoring, and heuristics to identify malware based on known suspicious and malicious activities. These activities include events, such as processes making unusual changes to existing files, modifying or creating automatic startup registry keys and startup locations (also known as autostart extensibility points, or ASEPs), and other changes to the file system or file structure.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> Turn on script scanning is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "DisableScriptScanning" is REG_DWORD = 0, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> Turn on script scanning to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83202r1144062_chk'
  tag severity: 'medium'
  tag gid: 'V-278668'
  tag rid: 'SV-278668r1144063_rule'
  tag stig_id: 'WNDF-AV-000064'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-83107r1133695_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 0 => Passes
    # Value = 1 => FAILS
    its('DisableScriptScanning') { should eq 0 }
  end

end
