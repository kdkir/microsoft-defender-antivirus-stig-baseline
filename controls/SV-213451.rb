control 'SV-213451' do
  title 'Microsoft Defender AV must be configured to turn on email scanning.'
  desc 'This policy setting allows the configuration of email scanning. When email scanning is enabled, the engine will parse the mailbox and mail files according to their specific format in order to analyze the mail bodies and attachments. Several email formats are currently supported, for example: pst (Outlook), dbx mbx mime (Outlook Express), binhex (Mac). If this setting is enabled, email scanning will be enabled. If this setting is disabled or not configured, email scanning will be disabled.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> "Turn on email scanning" is set to "Enabled".
  
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

If the value "DisableEmailScanning" is "REG_DWORD = 0", this is not a finding.
If the value is "1", this is a finding.

Alternate Check (if Microsoft Intune applied this setting):

Navigate to "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Policy Manager".

If the value "AllowEmailScanning" is "REG_DWORD = 1", this is not a finding.
If the value is "0", this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Scan >> "Turn on email scanning" to "Enabled".'
  impact 0.5
  tag check_id: 'C-14676r1260217_chk'
  tag severity: 'medium'
  tag gid: 'V-213451'
  tag rid: 'SV-213451r1260219_rule'
  tag stig_id: 'WNDF-AV-000027'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14674r1260218_fix'
  tag 'documentable'
  tag legacy: ['SV-89919', 'V-75239']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  only_if('Windows Defender is not the active antivirus product') { windows_defender_active.active? }

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan'
  intune_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Policy Manager'

  # Alternate check applies when Microsoft Intune applied this setting instead of Group Policy
  if !registry_key(registry_path).has_property?('DisableEmailScanning') && registry_key(intune_path).has_property?('AllowEmailScanning')
    describe registry_key(intune_path) do
      its('AllowEmailScanning') { should eq 1 }
    end
  else
    describe registry_key(registry_path) do
      its('DisableEmailScanning') { should eq 0 }
    end
  end

end
