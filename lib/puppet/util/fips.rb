
require 'puppet/util/platform'
# Method to determine whether where are running on a FIPs enabled host

module Puppet::Util::FIPS
  include Puppet::Util::Platform

  def fips_enabled?
    # We currently only plan to support FIPS on RHEL7
    # so we try to eliminate anything un-supported using
    # what we have available in lieu of not being able to specifically
    # check for it. 
    if Puppet::Util::Platform.windows?
      false
    end
  
    # REMIND - How to check if we are on posix+linux system to avoid
    # getting surprised on any odd-ball system that might not entertain
    # the below file query.
  
    fips_status_file = '/proc/sys/crypto/fips_enabled'
  
    if File.exist?(fips_status_file) && File.open(status_file, &:readline)[0].chr == '1'
      true
    else
      false
    end
  end
end
