control 'SV-278658' do
  title 'Microsoft Defender AV must control whether exclusions are visible to Local Admins.'
  desc 'Disabled (Default): If this setting is not configured or disabled, local admins can see exclusions in the Windows Security App or via PowerShell.

Enabled: If this setting is enabled, local admins no longer see the exclusion list in Windows Security App or via PowerShell.O13.

Note: Applying this setting will not remove exclusions, it only prevents them from being visible to local admins. This is reflected in Get-MpPreference'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Control whether or not exclusions are visible to Local Admins is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender

Criteria: If the value "HideExclusionsFromLocalAdmins" is REG_DWORD = 1, this is not a finding.

If the value is "0", this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Control whether or not exclusions are visible to Local Admins to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83192r1156518_chk'
  tag severity: 'medium'
  tag gid: 'V-278658'
  tag rid: 'SV-278658r1156519_rule'
  tag stig_id: 'WNDF-AV-000054'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83097r1133665_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender'

  describe registry_key(registry_path) do
    its('HideExclusionsFromLocalAdmins') { should eq 1 }
  end

end
