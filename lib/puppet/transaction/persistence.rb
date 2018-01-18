require 'yaml'
require 'puppet/util/yaml'
require 'puppet/util/better_encrypt'

# A persistence store implementation for storing information between
# transaction runs for the purposes of information inference (such
# as calculating corrective_change).
# @api private
class Puppet::Transaction::Persistence

  def initialize
    @old_data = {}
    @new_data = {"resources" => {}}
  end

  def bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16) }.join
  end

  # Obtain the full raw data from the persistence store.
  # @return [Hash] hash of data stored in persistence store
  def data
    @old_data
  end

  # Retrieve the system value using the resource and parameter name
  # @param [String] resource_name name of resource
  # @param [String] param_name name of the parameter
  # @return [Object,nil] the system_value
  def get_system_value(resource_name, param_name)
    if !@old_data["resources"].nil? &&
       !@old_data["resources"][resource_name].nil? &&
       !@old_data["resources"][resource_name]["parameters"].nil? &&
       !@old_data["resources"][resource_name]["parameters"][param_name].nil?
      @old_data["resources"][resource_name]["parameters"][param_name]["system_value"]
    else
      nil
    end
  end

  def set_system_value(resource_name, param_name, value)
    @new_data["resources"] ||= {}
    @new_data["resources"][resource_name] ||= {}
    @new_data["resources"][resource_name]["parameters"] ||= {}
    @new_data["resources"][resource_name]["parameters"][param_name] ||= {}
    @new_data["resources"][resource_name]["parameters"][param_name]["system_value"] = value
  end

  def copy_skipped(resource_name)
    @old_data["resources"] ||= {}
    old_value = @old_data["resources"][resource_name]
    if !old_value.nil?
      @new_data["resources"][resource_name] = old_value
    end
  end

  # Load data from the persistence store on disk.
  def load
    puts 'Inside Puppet::Transaction::Persistence.load method'
    filename = Puppet[:transactionstorefile]
    unless Puppet::FileSystem.exist?(filename)
      return
    end
    unless File.file?(filename)
      Puppet.warning(_("Transaction store file %{filename} is not a file, ignoring") % { filename: filename })
      return
    end

    result = nil
    Puppet::Util.benchmark(:debug, _("Loaded transaction store file in %{seconds} seconds")) do
      begin
        yaml = YAML.load_file(filename)
        # puts "Encrypted yaml: " + bin_to_hex(yaml)
        result = Puppet::Util::Encrypt.decrypt(yaml, Puppet::Util::Artifacts::TRANSACTIONSTORE)
        # result = Puppet::Util::Yaml.load(dec_file_cont, false, true)
       
=begin
        if result.is_a?(Hash)
          result.each do |key, value|
            puts key.to_s + " : " + value.to_s
          end
        end
=end

        # result = Puppet::Util::Yaml.load_file(filename, false, true)
      rescue Puppet::Util::Yaml::YamlLoadError => detail
        Puppet.log_exception(detail, _("Transaction store file %{filename} is corrupt (%{detail}); replacing") % { filename: filename, detail: detail }, { :level => :warning })

        begin
          File.rename(filename, filename + ".bad")
        rescue => detail
          Puppet.log_exception(detail, _("Unable to rename corrupt transaction store file: %{detail}") % { detail: detail })
          raise Puppet::Error, _("Could not rename corrupt transaction store file %{filename}; remove manually") % { filename: filename }, detail.backtrace
        end

        result = {}
      end
    end

    unless result.is_a?(Hash)
      Puppet.err _("Transaction store file %{filename} is valid YAML but not returning a hash. Check the file for corruption, or remove it before continuing.") % { filename: filename }
      return
    end

    @old_data = result
  end

  # Save data from internal class to persistence store on disk.
  def save
    puts 'Inside Puppet::Transaction::Persistence.save method'

    encrypted_new_data = Puppet::Util::Encrypt.encrypt(@new_data, Puppet::Util::Artifacts::TRANSACTIONSTORE)
    
=begin
    if @new_data.is_a?(Hash)
      @new_data.each do |key, value|
        puts key.to_s + " : " + value.to_s
      end
    end
    md = Marshal.dump(@new_data)
    puts "Marshaled new_data: " + md
    ml = Marshal.load(md)
    puts "Marshal load of md: "
    if ml.is_a?(Hash)
      ml.each do |key, value|
        puts key.to_s + " : " + value.to_s
      end
    else
      puts "Data after marshal load: " + ml
    end

    puts("Encrypted transaction store: " + bin_to_hex(encrypted_new_data))

    original_pt = Puppet::Util::Encrypt.decrypt(encrypted_new_data, Puppet::Util::Artifacts::TRANSACTIONSTORE)
    if original_pt.is_a?(Hash)
      puts "Original text: "
      original_pt.each do |key, value|
        puts key.to_s + " : " + value.to_s
      end
    end
=end

    # In case the 'secure_artifacts' setting is set to false, we might get plain text hash back
    # and in that case we want to write it as a yaml file.
    # When it actually gets encrypted then we can write it directly. 
    # ACTUALLY DISREGARD THE ABOVE
    Puppet::Util::Yaml.dump(encrypted_new_data, Puppet[:transactionstorefile])

    # Puppet::Util::Yaml.dump(@new_data, Puppet[:transactionstorefile])
  end

  # Use the catalog and run_mode to determine if persistence should be enabled or not
  # @param [Puppet::Resource::Catalog] catalog catalog being processed
  # @return [boolean] true if persistence is enabled
  def enabled?(catalog)
    catalog.host_config? && Puppet.run_mode.name == :agent
  end
end
