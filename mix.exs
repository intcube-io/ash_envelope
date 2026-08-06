defmodule AshEnvelope.MixProject do
  use Mix.Project

  @description """
  Envelope encryption primitives and key grant management for the Ash ecosystem.
  """

  @version "0.2.0"

  def project do
    [
      app: :ash_envelope,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      consolidate_protocols: Mix.env() == :prod,
      description: @description,
      deps: deps(),
      docs: &docs/0,
      dialyzer: [plt_add_apps: [:mix]],
      aliases: aliases(),
      package: package(),
      source_url: "https://github.com/intcube-io/ash_envelope",
      homepage_url: "https://github.com/intcube-io/ash_envelope"
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extra_section: "GUIDES",
      extras: [
        {"README.md", title: "Home"},
        "documentation/tutorials/getting-started-with-ash-envelope.md",
        "documentation/topics/how-envelope-encryption-works.md",
        "documentation/topics/reconciliation.md",
        "documentation/topics/user-driven-fulfillment.md",
        "documentation/proposals/reconcile-and-grant-requests.md",
        "CHANGELOG.md"
      ],
      groups_for_extras: [
        Tutorials: ~r"documentation/tutorials",
        Topics: ~r"documentation/topics",
        "About AshEnvelope": [
          "CHANGELOG.md"
        ]
      ],
      before_closing_head_tag: fn type ->
        if type == :html do
          """
          <script>
            if (location.hostname === "hexdocs.pm") {
              var script = document.createElement("script");
              script.src = "https://plausible.io/js/script.js";
              script.setAttribute("defer", "defer")
              script.setAttribute("data-domain", "ashhexdocs")
              document.head.appendChild(script);
            }
          </script>
          <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
          <script>
            document.addEventListener("DOMContentLoaded", function () {
              mermaid.initialize({ startOnLoad: false, theme: "default" });
              let id = 0;
              for (const codeEl of document.querySelectorAll("pre code.mermaid, pre code.language-mermaid")) {
                const preEl = codeEl.parentElement;
                const graphDefinition = codeEl.textContent;
                const graphEl = document.createElement("div");
                const graphId = "mermaid-graph-" + id++;
                mermaid.render(graphId, graphDefinition).then(({ svg, bindFunctions }) => {
                  graphEl.innerHTML = svg;
                  if (bindFunctions) bindFunctions(graphEl);
                  preEl.insertAdjacentElement("afterend", graphEl);
                  preEl.remove();
                });
              }
            });
          </script>
          """
        end
      end
    ]
  end

  defp deps do
    [
      {:ash, ash_version("~> 3.0")},
      {:ash_storage,
       ash_storage_version(
         git: "https://github.com/wln/ash_storage.git",
         branch: "blobio5/serving-disposition"
       )},
      {:spark, "~> 2.0"},
      {:plug, "~> 1.14", optional: true},
      {:mime, "~> 2.0", optional: true},
      {:oban, "~> 2.18", optional: true},
      {:igniter, "~> 0.5"},
      {:jason, "~> 1.0"},
      {:ex_doc, "~> 0.30", only: [:dev, :test], runtime: false},
      {:ex_check, "~> 0.12", only: [:dev, :test]},
      {:credo, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:dialyxir, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:sobelow, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:git_ops, "~> 2.5", only: [:dev, :test]},
      {:mix_audit, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:simple_sat, "~> 0.1", only: :test}
    ]
  end

  defp ash_version(default_version) do
    case System.get_env("ASH_VERSION") do
      nil -> default_version
      "local" -> [path: "../ash"]
      "main" -> [git: "https://github.com/ash-project/ash.git"]
      version -> "~> #{version}"
    end
  end

  defp ash_storage_version(default_version) do
    case System.get_env("ASH_STORAGE_VERSION") do
      nil -> default_version
      "local" -> [path: "../ash_storage_wip_20260602"]
      "main" -> [git: "https://github.com/ash-project/ash_storage.git"]
      version -> "~> #{version}"
    end
  end

  defp package do
    [
      maintainers: [
        "Marc Nickert"
      ],
      licenses: ["MIT"],
      files: ~w(lib .formatter.exs mix.exs README* LICENSE* CHANGELOG* documentation),
      links: %{
        "GitHub" => "https://github.com/intcube-io/ash_envelope",
        "Changelog" => "https://github.com/intcube-io/ash_envelope/blob/main/CHANGELOG.md",
        "Discord" => "https://discord.gg/HTHRaaVPUc",
        "Website" => "https://ash-hq.org",
        "Forum" => "https://elixirforum.com/c/elixir-framework-forums/ash-framework-forum"
      }
    ]
  end

  defp aliases do
    [
      sobelow: "sobelow --skip",
      credo: "credo --strict"
    ]
  end
end
