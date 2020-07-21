defmodule Mtuproxy.Utils do
  @moduledoc """
  Utils for socket, TLS and DNS
  """

  require Logger

  @cache_name :dns_cache
  @max_ttl 3 * 60 * 60 * 1000
  @re_ip ~r/^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$/

  @doc """
  Resolves a DNS A record securely.
  """

  def secure_arecord_resolve!(host) do
    if Regex.match?(@re_ip, host) do
      host
    else
      case Cachex.get(@cache_name, host) do
        {:ok, nil} ->
          {:ok, ip, ttl} = resolve_dns!(host)
          {:ok, _} = Cachex.put(@cache_name, host, ip, ttl: min(ttl * 1000, @max_ttl))
          ip

        {:ok, ip} ->
          Logger.debug("Cached #{host} #{ip}")
          ip
      end
    end
  end

  @doc """
  Stream data from src socket to dst socket.
  """
  def stream(dst, src) do
    data = Socket.Stream.recv!(src)

    if not is_nil(data) do
      Socket.Stream.send!(dst, data)

      stream(dst, src)
    end
  end

  @doc """
  Streams a tcp source socket to the destination until error happens in
  the recv/3 or send/2.
  """
  def tcp_stream(dst, src, opts \\ []) do
    with {:ok, data} when not is_nil(data) <- :gen_tcp.recv(src, opts[:mtu] || 0, 30_000),
         :ok <- :gen_tcp.send(dst, data) do
      tcp_stream(dst, src)
    end
  end

  @doc """
  Read HTTP Target.
  """
  def read_http_target(request) do
    case :gen_tcp.recv(request, 0) do
      {:ok, <<"CONNECT ", rest::binary>>} ->
        [target | _] = String.split(rest, " ")
        [host, port] = String.split(target, ":")
        {:ok, :ssl, host, String.to_integer(String.replace(port, "/", ""))}

      {:ok,
       <<22, 3, 1, _size::integer-16, 1, _handshake_size::binary-3, _, _, _rnd::binary-32,
         rest::binary>> = hello} ->
        host =
          rest
          # SESSION ID
          |> skip_ssl_property_8()
          # CIPHERS
          |> skip_ssl_property_16()
          # COMPRESSION
          |> skip_ssl_property_8()
          # Extensions
          |> take_ssl_property_16()
          |> find_server_name_extension()

        {:ok, :ssl_direct, host, hello}

      {:ok, http_data} ->
        {:ok, :http, http_data}

      {:error, _} ->
        :error
    end
  end

  defp find_server_name_extension(
         <<0, 0, _, _, _, _, _, host_size::unsigned-integer-16, rest::binary>>
       ) do
    <<host::binary-size(host_size), _::binary>> = rest
    host
  end

  defp find_server_name_extension(<<type::binary-2, rest::binary>>) do
    Logger.debug("NOSNI: #{inspect(type)} #{inspect(rest)}")

    rest
    |> skip_ssl_property_16()
    |> find_server_name_extension()
  end

  defp find_server_name_extension(bad) do
    raise "Bad SNI: #{inspect(bad)}"
  end

  defp skip_ssl_property_16(<<size::unsigned-integer-16, rest::binary>>) do
    <<_skip::binary-size(size), cut::binary>> = rest
    cut
  end

  defp skip_ssl_property_8(<<size::unsigned-integer-8, rest::binary>>) do
    <<_skip::binary-size(size), cut::binary>> = rest
    cut
  end

  defp take_ssl_property_16(<<size::unsigned-integer-16, rest::binary>>) do
    <<take::binary-size(size), _skip::binary>> = rest
    take
  end

  def connect_ssl_remote(host, port, opts \\ []) do
    if opts[:sni] do
      Socket.SSL.connect(host, port, server_name: opts[:sni])
    else
      Socket.SSL.connect(host, port, server_name: "gmail.com")
    end
  end

  def connect_tcp_remote(host, port, _opts \\ []) do
    Socket.TCP.connect(host, port)
  end

  ###
  # Helpers
  ###

  defp resolve_dns!(host) do
    case HTTPoison.get("https://cloudflare-dns.com/dns-query?name=#{host}&type=A",
           accept: "application/dns-json"
         ) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        %{"data" => host_ip, "TTL" => ttl} = Jason.decode!(body)["Answer"] |> List.last()
        Logger.debug("RESOLVER #{host} => #{host_ip}")
        {:ok, host_ip, ttl}

      error ->
        raise "Name not resolved #{inspect(error)}"
    end
  end
end
