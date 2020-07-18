defmodule Mtuproxy.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  def start(_type, _args) do
    port = read_integer_env("PROXY_PORT") || 443

    Logger.configure(level: :error)

    children = [
      # Starts a worker by calling: Mtuproxy.Worker.start_link(arg)
      {Mtuproxy, port: port}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Mtuproxy.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp read_integer_env(env) do
    case System.get_env(env) do
      nil ->
        nil

      val ->
        {int, ""} = Integer.parse(val)
        int
    end
  end
end
