import streamlit as st


def show_table(df, empty_msg="No records.", **kwargs):
    """Dataframe with an empty-state fallback."""
    if df is None or df.empty:
        st.info(empty_msg)
        return False
    st.dataframe(df, width='stretch', hide_index=True, **kwargs)
    return True


def download_df(df, label, filename):
    """Small download button bound to a dataframe."""
    if df is None or df.empty:
        return
    st.download_button(
        label,
        data=df.to_csv(index=False),
        file_name=filename,
        mime="text/csv",
    )