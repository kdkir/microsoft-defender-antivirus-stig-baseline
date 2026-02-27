control 'SV-278676' do
  title 'Microsoft Defender AV must scan excluded files and directories during quick scans.'
  desc 'In Microsoft Defender Antivirus, when an exclusion for a file or folder is created, it will generally be skipped during both real-time protection and on-demand scans (including quick scans and full scans). However, with newer releases, the option exists to configure quick scans to include files and directories that are otherwise excluded from real-time protection.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> Scan excluded files and directories during quick scans is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

Criteria: If the value "QuickScanIncludeExclusions" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> Scan excluded files and directories during quick scans to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83210r1144074_chk'
  tag severity: 'medium'
  tag gid: 'V-278676'
  tag rid: 'SV-278676r1144075_rule'
  tag stig_id: 'WNDF-AV-000072'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-83115r1133719_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 1 => Passes
    # Value = 0 => FAILS
    its('QuickScanIncludeExclusions') { should be_nil.or eq 1 }
  end

end
