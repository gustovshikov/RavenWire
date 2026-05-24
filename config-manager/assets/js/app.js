(() => {
  const csrfToken = document.querySelector("meta[name='csrf-token']")?.getAttribute("content")

  if (!window.Phoenix || !window.LiveView || !csrfToken) {
    return
  }

  const Hooks = {
    MetricsChart: {
      mounted() {
        this.renderChart()
      },

      updated() {
        this.renderChart()
      },

      destroyed() {
        if (this.chart) {
          this.chart.destroy()
        }
      },

      renderChart() {
        if (!window.Chart) return

        const payload = JSON.parse(this.el.dataset.chart || "{}")
        const canvas = this.el.querySelector("canvas")
        if (!canvas || !payload.series) return

        if (this.chart) {
          this.chart.destroy()
        }

        const labels = Array.from(
          new Set(payload.series.flatMap((series) => series.points.map((point) => point.label)))
        ).sort()

        const palette = [
          "#2563eb",
          "#dc2626",
          "#16a34a",
          "#9333ea",
          "#d97706",
          "#0891b2",
          "#be123c",
          "#4f46e5",
          "#0f766e",
          "#7c2d12"
        ]

        this.chart = new window.Chart(canvas, {
          type: "line",
          data: {
            labels,
            datasets: payload.series.map((series, index) => {
              const values = new Map(series.points.map((point) => [point.label, point.value]))
              return {
                label: series.label,
                data: labels.map((label) => values.get(label) ?? null),
                borderColor: palette[index % palette.length],
                backgroundColor: palette[index % palette.length],
                borderWidth: 2,
                pointRadius: 2,
                tension: 0.15,
                spanGaps: true
              }
            })
          },
          options: {
            animation: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? false : undefined,
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: "nearest", intersect: false },
            plugins: {
              legend: { display: payload.series.length > 1 },
              tooltip: {
                callbacks: {
                  label(context) {
                    const unit = payload.unit || ""
                    const value = context.parsed.y
                    return `${context.dataset.label}: ${value}${unit && unit !== "bytes" ? ` ${unit}` : ""}`
                  }
                }
              }
            },
            scales: {
              x: { ticks: { maxTicksLimit: 8 } },
              y: { beginAtZero: false, title: { display: Boolean(payload.unit), text: payload.unit || "" } }
            }
          }
        })
      }
    }
  }

  const liveSocket = new window.LiveView.LiveSocket("/live", window.Phoenix.Socket, {
    hooks: Hooks,
    params: { _csrf_token: csrfToken }
  })

  liveSocket.connect()
  window.liveSocket = liveSocket
})()
