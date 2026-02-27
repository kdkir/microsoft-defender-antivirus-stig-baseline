control 'SV-278677' do
  title 'Microsoft Defender AV must convert warn verdict to block.'
  desc 'If a site URL has an unknown or uncertain reputation, a toast notification presents the user with the following options:

- Ok: The toast notification is released (removed), and the attempt to access the site is ended.

- Unblock: The user has access to the site for 24 hours, at which point the block is reenabled. The user can continue to use Unblock to access the site until such time that the administrator prohibits (blocks) the site, thus removing the option to Unblock.

- Feedback: The toast notification presents the user with a link to submit a ticket, which the user can use to submit feedback to the administrator in an attempt to justify access to the site.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Network Inspection System >> Convert warn verdict to block is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\NIS

Criteria: If the value "EnableConvertWarnToBlock" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MpEngine >> Convert warn verdict to block to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83211r1144076_chk'
  tag severity: 'medium'
  tag gid: 'V-278677'
  tag rid: 'SV-278677r1144077_rule'
  tag stig_id: 'WNDF-AV-000074'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83116r1134122_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\NIS'

  describe registry_key(registry_path) do
    # Missing value => nil => passes
    # Value = 1 => Passes
    # Value = 0 => FAILS
    its('EnableConvertWarnToBlock') { should be_nil.or eq 1 }
  end

end
