control 'SV-278650' do
  title 'Microsoft Defender AV must use advanced protection against ransomware.'
  desc "This policy setting provides an extra layer of protection against ransomware. It uses both client and cloud heuristics to determine whether a file resembles ransomware. 
This rule doesn't block files that have one or more of the following characteristics:

- The file is found to be unharmful in the Microsoft cloud.
- The file is a valid signed file.
-  The file is prevalent enough to not be considered as ransomware.
- The rule tends to err on the side of caution to prevent ransomware."
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "c1db55ab-c21a-4637-bb3f-a12568109d35" is REG_SZ = 1, this is not a finding.

If the value is other than 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> Configure Attack Surface Reduction rules to "Enabled".

Under the policy option "Set the state for each ASR rule:", then click "Show".

Enter GUID "c1db55ab-c21a-4637-bb3f-a12568109d35" in the "Value Name" column.

Enter "1" in the "Value" column.

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83184r1144035_chk'
  tag severity: 'medium'
  tag gid: 'V-278650'
  tag rid: 'SV-278650r1144036_rule'
  tag stig_id: 'WNDF-AV-000046'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83089r1134275_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
