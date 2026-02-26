control 'SV-278654' do
  title 'Microsoft Defender AV must block Office communication application from creating child processes.'
  desc "This policy setting prevents Outlook from creating child processes while still allowing legitimate Outlook functions. This rule protects against social engineering attacks and prevents exploiting code from abusing vulnerabilities in Outlook. It also protects against Outlook rules and forms exploits that attackers can use when a user's credentials are compromised."
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "26190899-1602-49e8-8b27-eb1d0a1ce869" is REG_SZ = 1, this is not a finding.

If the value is other than 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "26190899-1602-49e8-8b27-eb1d0a1ce869" in the "Value Name" column.

Enter "1" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83188r1144046_chk'
  tag severity: 'medium'
  tag gid: 'V-278654'
  tag rid: 'SV-278654r1144047_rule'
  tag stig_id: 'WNDF-AV-000050'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83093r1134287_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules'

  describe registry_key(registry_path) do
    it { should exist }
    it { should have_property '26190899-1602-49e8-8b27-eb1d0a1ce869' }
    its('26190899-1602-49e8-8b27-eb1d0a1ce869') { should eq "1" }
  end

end
