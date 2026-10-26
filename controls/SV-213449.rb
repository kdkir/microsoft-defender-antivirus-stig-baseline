control 'SV-213449' do
  title 'Microsoft Defender AV must be configured to scan removable drives.'
  desc 'This policy setting allows the management of whether or not to scan for malicious software and unwanted software in the contents of removable drives such as USB flash drives when running a full scan. If this setting is enabled, removable drives will be scanned during any type of scan. If this setting is disabled or not configured, removable drives will not be scanned during a full scan. Removable drives may still be scanned during quick scan and custom scan.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> "Scan removable drives" is set to "Enabled".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

If the value "DisableRemovableDriveScanning" is "REG_DWORD = 0", this is not a finding.
If the value is "1", this is a finding.

Alternate Check (if Microsoft Intune applied this setting):

Navigate to "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Policy Manager".

If the value "AllowFullScanRemovableDriveScanning" is "REG_DWORD = 1", this is not a finding.
If the value is "0", this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> Scan >> "Scan removable drives" to "Enabled".'
  impact 0.5
  tag check_id: 'C-14674r1260213_chk'
  tag severity: 'medium'
  tag gid: 'V-213449'
  tag rid: 'SV-213449r1260214_rule'
  tag stig_id: 'WNDF-AV-000025'
  tag gtitle: 'SRG-APP-000073'
  tag fix_id: 'F-14672r820195_fix'
  tag 'documentable'
  tag legacy: ['SV-89915', 'V-75235']
  tag cci: ['CCI-000870']
  tag nist: ['MA-3 (2)']

  only_if('Windows Defender is not the active antivirus product') { windows_defender_active.active? }

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan'
  intune_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Policy Manager'

  # Alternate check applies when Microsoft Intune applied this setting instead of Group Policy
  if !registry_key(registry_path).has_property?('DisableRemovableDriveScanning') && registry_key(intune_path).has_property?('AllowFullScanRemovableDriveScanning')
    describe registry_key(intune_path) do
      its('AllowFullScanRemovableDriveScanning') { should eq 1 }
    end
  else
    describe registry_key(registry_path) do
      its('DisableRemovableDriveScanning') { should eq 0 }
    end
  end

end
