control 'SV-213455' do
  title 'Microsoft Defender AV must be configured for automatic remediation action to be taken for threat alert level Severe.'
  desc 'This policy setting allows the customization of which automatic remediation action will be taken for each threat alert level. Threat alert levels should be added under the Options for this setting. Each entry must be listed as a name value pair. The name defines a threat alert level. The value contains the action ID for the remediation action that should be taken. 

Valid threat alert levels are:  
1 = Low  
2 =  Medium  
4 = High  
5 = Severe  

Valid remediation action values are: 
2 = Quarantine  
3 = Remove  
6 = Ignore'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Threats >> "Specify threat alert levels at which default action should not be taken when detected" is set to "Enabled".  

Click the "Show…" box option and verify the "Value name" field contains a value of "5" and the "Value" field  contains "2".  A value of "3" in the "Value" field is more restrictive and also an acceptable value.
  
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction

If the value "5" is "REG_SZ = 2 (or 3)", this is not a finding.
If the value is "6", this is a finding.

Alternate Check (if Microsoft Intune applied this setting):

Navigate to "HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Policy Manager".

If the value "ThreatSeverityDefaultAction" is "REG_DWORD = 1 (or 2)", this is not a finding.
If the value is "0", this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Threats >> "Specify threat alert levels at which default action should not be taken when detected" to "Enabled". 

Select the "Show…" option box and enter "5" in the "Value name" field and enter "2" in the "Value" field.'
  impact 0.5
  tag check_id: 'C-14680r1271017_chk'
  tag severity: 'medium'
  tag gid: 'V-213455'
  tag rid: 'SV-213455r1271018_rule'
  tag stig_id: 'WNDF-AV-000031'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-14678r823078_fix'
  tag 'documentable'
  tag legacy: ['SV-89927', 'V-75247']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']

  only_if('Windows Defender is not the active antivirus product') { windows_defender_active.active? }

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction'
  intune_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Policy Manager'

  # Alternate check applies when Microsoft Intune applied this setting instead of Group Policy
  if !registry_key(registry_path).has_property?('5') && registry_key(intune_path).has_property?('ThreatSeverityDefaultAction')
    describe registry_key(intune_path) do
      its('ThreatSeverityDefaultAction') { should be_in [1, 2] }
    end
  else
    describe registry_key(registry_path) do
      it { should exist }
      it { should have_property '5' }
      its('5') { should be_in ['2', '3'] }
    end
  end

end
