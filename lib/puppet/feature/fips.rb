require 'puppet/util/feature'

# Whether fips mode is enabled or not
Puppet.features.add(:fips_enabled) do
  begin
    # We currently only plan to support FIPS on RHEL7
    # so we try to eliminate anything un-supported using
    # what we have available in lieu of not being able to specifically
    # check for it. 
    if !Puppet.features.posix? 
      return false
    end

    fips_status_file = '/proc/sys/crypto/fips_enabled'

    if File.exist?(fips_status_file) && File.open(status_file, &:readline)[0].chr == '1'
      true
    else
      false
    end
  end
end
