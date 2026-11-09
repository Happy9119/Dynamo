import html
import streamlit as st


def empty_state(title, body, icon="○", cta_label=None, cta_path=None):
    st.markdown(
        f'<div class="empty-state">'
        f'  <div class="empty-icon">{html.escape(icon)}</div>'
        f'  <div class="empty-title">{html.escape(title)}</div>'
        f'  <div class="empty-body">{html.escape(body)}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    if cta_label and cta_path:
        _, mid, _ = st.columns([1, 2, 1])
        with mid:
            if st.button(cta_label, width="stretch", type="primary",
                         key=f"empty_cta_{title}"):
                st.switch_page(cta_path)


def error_state(title, body, retry_key=None):
    st.markdown(
        f'<div class="empty-state empty-error">'
        f'  <div class="empty-icon">⚠</div>'
        f'  <div class="empty-title">{html.escape(title)}</div>'
        f'  <div class="empty-body">{html.escape(body)}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    if retry_key:
        _, mid, _ = st.columns([1, 2, 1])
        with mid:
            if st.button("Retry", key=retry_key, width="stretch"):
                st.rerun()