/* AI 채팅방: 보내기를 fetch 로 처리해 페이지를 새로 읽지 않고 대화를 이어 붙인다. 글자는 모두 textContent 로만 넣는다(HTML 로 해석하지 않음).
   JS 가 꺼져 있어도 폼이 그대로 전송된다(서버가 같은 처리를 하고 대화방으로 이동). CSP(script-src 'self') 때문에 인라인 스크립트는 쓰지 않는다. */
(function () {
  "use strict";
  var form = document.getElementById("chat-form");
  if (!form || !window.fetch) { return; }
  var thread = document.getElementById("thread");
  var scroller = document.getElementById("chat-scroll");
  var empty = document.getElementById("chat-empty");
  var errorBox = document.getElementById("chat-error");
  var convInput = document.getElementById("conversation-id");
  var box = document.getElementById("chat-message");
  var button = document.getElementById("chat-submit");
  var list = document.getElementById("chat-list");
  var busy = false;

  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function stamp() {
    var d = new Date();
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
  }
  function toBottom() { scroller.scrollTop = scroller.scrollHeight; }
  function showError(text) { errorBox.textContent = text; errorBox.hidden = !text; }

  function addMessage(who, text) {
    var li = document.createElement("li");
    li.className = "msg msg-" + who;
    var head = document.createElement("div");
    head.className = "msg-head";
    var name = document.createElement("span");
    name.className = "msg-who";
    name.textContent = who === "user" ? "나" : "어시스턴트";
    var time = document.createElement("time");
    time.textContent = stamp();
    head.appendChild(name);
    head.appendChild(time);
    var body = document.createElement("div");
    body.className = "msg-body";
    body.textContent = text;
    li.appendChild(head);
    li.appendChild(body);
    thread.appendChild(li);
    if (empty) { empty.hidden = true; }
    toBottom();
    return body;
  }

  function typeInto(body, text, done) {
    /* 답이 한 번에 오므로 화면에서만 조금씩 보여 준다(긴 답은 빠르게). 실제 내용은 이미 서버에 저장되어 있다. */
    var step = Math.max(2, Math.ceil(text.length / 120));
    var i = 0;
    body.textContent = "";
    (function tick() {
      i = Math.min(text.length, i + step);
      body.textContent = text.slice(0, i);
      toBottom();
      if (i < text.length) { window.setTimeout(tick, 16); } else { done(); }
    })();
  }

  function touchList(id, title) {
    if (!list || !id) { return; }
    var placeholder = list.querySelector(".chat-list-empty");
    if (placeholder) { placeholder.remove(); }
    var found = null;
    list.querySelectorAll("a.chat-item").forEach(function (a) {
      a.classList.remove("active");
      a.removeAttribute("aria-current");
      if (a.getAttribute("href") === "/chat/c/" + id) { found = a; }
    });
    var li;
    if (found) {
      li = found.parentNode;
    } else {
      li = document.createElement("li");
      found = document.createElement("a");
      found.className = "chat-item";
      found.href = "/chat/c/" + id;
      var t = document.createElement("span");
      t.className = "chat-item-title";
      t.textContent = title || "새 대화";
      var time = document.createElement("time");
      found.appendChild(t);
      found.appendChild(time);
      li.appendChild(found);
    }
    found.classList.add("active");
    found.setAttribute("aria-current", "page");
    found.querySelector("time").textContent = stamp().slice(5);
    list.insertBefore(li, list.firstChild);
  }

  function send() {
    if (busy) { return; }
    var text = box.value.trim();
    if (!text) { return; }
    busy = true;
    button.disabled = true;
    showError("");
    addMessage("user", text);
    box.value = "";
    var pending = addMessage("assistant", "답변을 만드는 중입니다");
    pending.parentNode.classList.add("msg-pending");
    var data = new FormData(form);
    data.set("message", text);
    fetch(form.action, { method: "POST", body: data, credentials: "same-origin",
                         headers: { "X-Requested-With": "fetch", "Accept": "application/json" } })
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: "응답을 읽지 못했습니다." }; }); })
      .then(function (res) {
        pending.parentNode.classList.remove("msg-pending");
        if (!res.ok) {
          pending.parentNode.remove();
          showError(res.error || "보내지 못했습니다. 잠시 후 다시 시도하세요.");
          box.value = text;
          return;
        }
        convInput.value = String(res.conversation_id);
        if (window.history && window.history.replaceState) { window.history.replaceState(null, "", "/chat/c/" + res.conversation_id); }
        touchList(res.conversation_id, res.title);
        typeInto(pending, res.reply, function () { toBottom(); });
      })
      .catch(function () {
        pending.parentNode.remove();
        showError("서버에 연결하지 못했습니다. 잠시 후 다시 시도하세요.");
        box.value = text;
      })
      .then(function () { busy = false; button.disabled = false; box.focus(); });
  }

  form.addEventListener("submit", function (e) { e.preventDefault(); send(); });
  box.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing && e.keyCode !== 229) { e.preventDefault(); send(); }   /* 한글 조합 중 Enter 는 보내지 않는다 */
  });
  toBottom();
})();
