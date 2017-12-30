require 'puppet/resource/catalog'
require 'puppet/indirector/json'
require 'puppet/util/encrypt'

class Puppet::Resource::Catalog::Json < Puppet::Indirector::JSON
  include Puppet::Util::Encrypt
  desc "Store catalogs as flat files, serialized using JSON."

  def from_json(text)
    utf8 = text.force_encoding(Encoding::UTF_8)

    if utf8.valid_encoding?
      model.convert_from('json', utf8)
    else
      Puppet.info(_("Unable to deserialize catalog from json, retrying with pson"))
      model.convert_from('pson', text.force_encoding(Encoding::BINARY))
    end
  end

  def to_json(object)
    object.render('json')
  rescue Puppet::Network::FormatHandler::FormatError
    Puppet.info(_("Unable to serialize catalog to json, retrying with pson"))
    object.render('pson').force_encoding(Encoding::BINARY)
  end

  # Overloading to be to encrypt the catalog 
  def save(request)
    filename = path(request.key)
    FileUtils.mkdir_p(File.dirname(filename))

    # Puppet::Util.replace_file(filename, 0660) {|f| f.print Puppet::Util::Encrypt.encrypt(to_json(request.instance).force_encoding(Encoding::BINARY))}
    Puppet::Util.replace_file(filename, 0660) {|f| f.print encrypt(to_json(request.instance).force_encoding(Encoding::BINARY))}
  rescue TypeError => detail
    Puppet.log_exception(detail, _("Could not save %{json} %{request}: %{detail}") % { json: self.name, request: request.key, detail: detail })
  end

  # Overloading to be able to decrypt the catalog 
  def load_json_from_file(file, key)
    json = nil

    begin
      json = decrypt(File.read(file))

      # TODO:: How to specify binary encoding when attempting to read & decrypt above
      # Below was the original implementation
      # json = Puppet::FileSystem.read(file, :encoding => Encoding::BINARY)
    rescue Errno::ENOENT
      return nil
    rescue => detail
      raise Puppet::Error, _("Could not read JSON data for %{name} %{key}: %{detail}") % { name: indirection.name, key: key, detail: detail }, detail.backtrace
    end

    begin
      return from_json(json)
    rescue => detail
      raise Puppet::Error, _("Could not parse JSON data for %{name} %{key}: %{detail}") % { name: indirection.name, key: key, detail: detail }, detail.backtrace
    end
  end

end
