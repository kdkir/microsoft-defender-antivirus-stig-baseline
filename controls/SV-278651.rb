control 'SV-278651' do
  title 'Microsoft Defender AV must block process creations originating from PSExec and WMI commands.'
  desc "This policy setting blocks processes created through PsExec and WMI from running. Both PsExec and WMI can remotely execute code. There is a risk of malware abusing functionality of PsExec and WMI for command and control purposes, or to spread an infection throughout an organization's network."
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "d1e49aac-8f56-4280-b9ba-993a6d77406c" is REG_SZ = 2, this is not a finding.

If the value is other than 2, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "d1e49aac-8f56-4280-b9ba-993a6d77406c" in the "Value Name" column.

Enter "2" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83185r1144037_chk'
  tag severity: 'medium'
  tag gid: 'V-278651'
  tag rid: 'SV-278651r1144039_rule'
  tag stig_id: 'WNDF-AV-000047'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83090r1144038_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules'

  describe registry_key(registry_path) do
    it { should exist }
    it { should have_property 'd1e49aac-8f56-4280-b9ba-993a6d77406c' }
    its('d1e49aac-8f56-4280-b9ba-993a6d77406c') { should eq "2" }
  end

end
