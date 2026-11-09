"""Small, consistent Plotly charts."""
import plotly.express as px
import streamlit as st

PURPLE = "#7C3AED"
RISK_COLORS = {
    "Critical": "#991B1B",  # Dark Red
    "High":     "#DC2626",  # Red
    "Medium":   "#EA580C",  # Orange
    "Low":      "#CA8A04",  # Yellow
    "Info":     "#2563EB",  # Light Blue
}

DEFAULT_HEIGHT = 200


def chart(fig, height: int = DEFAULT_HEIGHT):
    """Render a chart at a small, consistent size. Theme follows Streamlit."""
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=20, b=10),
    )
    st.plotly_chart(fig, width="stretch", theme="streamlit")


def risk_bar(risk_df, height: int = DEFAULT_HEIGHT):
    """risk_df: columns=['severity', 'count']."""
    fig = px.bar(
        risk_df, x="severity", y="count", color="severity",
        color_discrete_map=RISK_COLORS, template="plotly_white",
        category_orders={"severity": ["Critical", "High", "Medium", "Low"]},
    )
    fig.update_layout(showlegend=False, xaxis_title="", yaxis_title="Assets")
    chart(fig, height)


def tech_bar(tech_df, height: int = DEFAULT_HEIGHT, top: int = 12):
    """tech_df: columns=['Technology','Count']."""
    if tech_df.empty:
        st.info("No technologies found.")
        return
    df = tech_df.head(top).sort_values("Count")
    fig = px.bar(
        df, x="Count", y="Technology", orientation="h",
        template="plotly_white", color_discrete_sequence=[PURPLE],
    )
    fig.update_layout(showlegend=False, yaxis_title="")
    chart(fig, height)


def horizontal_bar(df, x: str, y: str, height: int = DEFAULT_HEIGHT,
                   top: int = 15, color: str = PURPLE):
    df = df.head(top).sort_values(x)
    fig = px.bar(
        df, x=x, y=y, orientation="h",
        template="plotly_white", color_discrete_sequence=[color],
    )
    fig.update_layout(showlegend=False, yaxis_title="")
    chart(fig, height)


def pie(df, names: str, values: str, height: int = DEFAULT_HEIGHT,
        color_map=None):
    fig = px.pie(
        df, names=names, values=values, template="plotly_white",
        color=names, color_discrete_map=color_map,
        color_discrete_sequence=px.colors.sequential.Purp_r,
    )
    chart(fig, height)