import html
import streamlit as st

def _esc(v):
    return html.escape(str(v), quote=True)

def breadcrumb(*crumbs):

    parts = []
    for i, c in enumerate(crumbs):
        is_last = (i == len(crumbs) - 1)
        if isinstance(c, tuple):
            label, url = c
            parts.append(
                f'<a href="{_esc(url)}" target="_self">{_esc(label)}</a>'
            )
        else:
            if is_last:
                parts.append(f'<span class="crumb-current">{c}</span>')
            else:
                parts.append(f'<span>{c}</span>')

    sep = '<span class="crumb-sep">/</span>'
    html_str = f'<div class="breadcrumb">{sep.join(parts)}</div>'
    st.markdown(html_str, unsafe_allow_html=True)