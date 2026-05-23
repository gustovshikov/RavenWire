(() => {
  const csrfToken = document.querySelector("meta[name='csrf-token']")?.getAttribute("content")

  if (!window.Phoenix || !window.LiveView || !csrfToken) {
    return
  }

  const liveSocket = new window.LiveView.LiveSocket("/live", window.Phoenix.Socket, {
    params: { _csrf_token: csrfToken }
  })

  liveSocket.connect()
  window.liveSocket = liveSocket
})()
