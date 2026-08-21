window.DiskActivityPlus = window.DiskActivityPlus || (function () {
  'use strict';

  function escapeHtml(value) {
    var node = document.createElement('div');
    node.textContent = value == null ? '' : String(value);
    return node.innerHTML;
  }

  function actorLabel(entry) {
    var container = String((entry && entry.container) || '').trim();
    var process = String((entry && entry.process) || 'unknown').trim();
    return container ? container + (process && process !== container ? ' (' + process + ')' : '') : process;
  }

  function formatTime(milliseconds) {
    return milliseconds ? new Date(Number(milliseconds)).toLocaleString() : '-';
  }

  function createPoller(options) {
    var interval = options.interval || 5000;
    var timeout = options.timeout || 3000;
    var timer = null;
    var request = null;
    var stopped = false;

    function schedule(delay) {
      if (stopped) return;
      clearTimeout(timer);
      timer = setTimeout(refresh, delay);
    }

    function refresh() {
      if (stopped) return;
      if (document.hidden) {
        schedule(interval);
        return;
      }
      if (request) return;

      request = $.ajax({
        url: options.url,
        method: options.method || 'GET',
        dataType: options.dataType || 'json',
        cache: false,
        timeout: timeout
      });

      request.done(function (data) {
        if (typeof options.onData === 'function') options.onData(data);
      });
      request.fail(function (xhr, status) {
        if (status !== 'abort' && typeof options.onError === 'function') options.onError(xhr, status);
      });
      request.always(function () {
        request = null;
        schedule(interval);
      });
    }

    function stop() {
      stopped = true;
      clearTimeout(timer);
      if (request) request.abort();
      request = null;
    }

    $(window).on('pagehide.diskActivityPlus beforeunload.diskActivityPlus', stop);
    $(document).on('visibilitychange.diskActivityPlus', function () {
      if (!document.hidden && !request) schedule(0);
    });

    return {
      start: refresh,
      refresh: function () { schedule(0); },
      stop: stop
    };
  }

  return {
    escapeHtml: escapeHtml,
    actorLabel: actorLabel,
    formatTime: formatTime,
    createPoller: createPoller
  };
})();
