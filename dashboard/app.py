"""app.py"""

from __future__ import annotations
from typing import Any, Hashable
import json
import os
import sys
import pathlib
import dash
import dash_auth
from dash import Input, Output, State, html, dcc
import dash_bootstrap_components as dbc
from dash_bootstrap_templates import load_figure_template
from dotenv import load_dotenv
import plotly.express as px
import plotly.graph_objects as go
from utils import (
    generate_threat_risk_score_graph, generate_threat_priorites_graph,
    generate_threat_source_graph, generate_threat_destination_graph,
    generate_aware_threats_over_time_graph, generate_threat_locations_map,
    generate_events_details_table, filter_logic)

# Load credentials from .env file as environment variables
try:
    load_dotenv()
    try:
        USERNAME = os.environ["DASHBOARD_USERNAME"]
        PASSWORD = os.environ["DASHBOARD_PASSWORD"]
    except KeyError:
        USERNAME = os.environ["FlaskDashboardUsername"]
        PASSWORD = os.environ["FlaskDashboardPassword"]
    SECRET_KEY = os.environ["FlaskDashboardSecretKey"]
except KeyError as err:
    print(err, "No valid keys found in env.")
    sys.exit(1)

# Define APP_PATH as the absolute path of the directory containing this script.
APP_PATH = str(pathlib.Path(__file__).parent.resolve())

# Application setup
load_figure_template("darkly")
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    meta_tags=[{
        "name": "viewport",
        "content": "width=device-width, initial-scale=1"
    }],
)
app.server.secret_key = SECRET_KEY
auth = dash_auth.BasicAuth(app, {USERNAME: PASSWORD})
app.title = "Threat Overview Dashboard"
server = app.server
app.config["suppress_callback_exceptions"] = True
PLOTLY_LOGO = r"assets/plotly_logo.png"

# Dashboard date range
try:
    with open(f"{APP_PATH}/data/events.json", encoding="utf-8") as events:
        json_data = json.load(events)
        start_date, end_date = json_data["AWARE Threats"]["Date"][
            0], json_data["AWARE Threats"]["Date"][-1]
except (FileNotFoundError, KeyError):
    start_date, end_date = "-", "-"

# Navbar Links
links = dbc.Nav([
    dbc.NavItem(
        dbc.NavLink("plasticuproject's blog",
                    href="https://plasticuproject.com/about",
                    external_link=True)),
    dbc.NavItem(
        dbc.NavLink("plasticuproject's github",
                    href="https://github.com/plasticuproject",
                    external_link=True)),
])

# Navbar
navbar = dbc.Navbar(
    dbc.Container(
        [
            html.A(
                dbc.Row(
                    [
                        dbc.Col(html.Img(src=PLOTLY_LOGO, height="30px")),
                        # dbc.Col(
                        #     dbc.NavbarBrand("plasticuproject",
                        #                     className="ms-2")),
                    ],
                    align="center",
                    className="g-0",
                ),
                href="https://plotly.com/",
                style={"textDecoration": "none"},
            ),
            dbc.NavbarToggler(id="navbar-toggler", n_clicks=0),
            dbc.Collapse(
                dbc.Nav(
                    [links],
                    className="ms-auto",
                    navbar=True,
                    style={"paddingRight": "0px"},
                ),
                id="navbar-collapse",
                navbar=True,
            ),
        ],
        fluid=True,
        style={
            "paddingLeft": "30px",
            "paddingRight": "30px"
        },
    ),
    color="dark",
    dark=True,
    className="mb-5",
)

# Title text
title = html.Div(
    dbc.Container([
        html.Div([
            html.H3("Threat Overview Dashboard", style={"textAlign": "center"
                                                        }),
            html.H5(f"{start_date} thru {end_date}",
                    style={
                        "textAlign": "center",
                        "fontStyle": "italic"
                    })
        ])
    ],
                  style={
                      "display": "flex",
                      "justifyContent": "center"
                  }))

# Graph/Chart card containers
threat_risk_score_graph = html.Div(
    [
        html.H4("Threat Risk Score",
                style={
                    "paddingLeft": "20px",
                    "paddingTop": "5px"
                }),
        dcc.Graph(id="trs-graph", figure=generate_threat_risk_score_graph()),
    ],
    style={
        "marginBottom": "30px",
        "marginTop": "30px",
        "boxShadow": "0 4px 6px 0 rgba(0, 0, 0, 0.5)",
        # "maxWidth": "500px",
    })

threat_priorities_graph = html.Div(
    [
        html.H4("Threat Priorities",
                style={
                    "paddingLeft": "20px",
                    "paddingTop": "5px"
                }),
        dcc.Graph(id="tp-graph", figure=generate_threat_priorites_graph()),
    ],
    style={
        "marginBottom": "30px",
        "marginTop": "30px",
        "boxShadow": "0 4px 6px 0 rgba(0, 0, 0, 0.5)",
        # "maxWidth": "500px",
    })

threat_source_graph = html.Div(
    [
        html.H4("Threat Sources",
                style={
                    "paddingLeft": "20px",
                    "paddingTop": "5px"
                }),
        dcc.Graph(id="ts-graph", figure=generate_threat_source_graph()),
    ],
    style={
        "marginBottom": "30px",
        "marginTop": "30px",
        "boxShadow": "0 4px 6px 0 rgba(0, 0, 0, 0.5)",
        # "maxWidth": "500px",
    })

threat_destination_graph = html.Div(
    [
        html.H4("Threat Destinations",
                style={
                    "paddingLeft": "20px",
                    "paddingTop": "5px"
                }),
        dcc.Graph(id="td-graph", figure=generate_threat_destination_graph()),
    ],
    style={
        "marginBottom": "30px",
        "marginTop": "30px",
        "boxShadow": "0 4px 6px 0 rgba(0, 0, 0, 0.5)",
        # "maxWidth": "500px",
    })

aware_threats_over_time_graph = html.Div(
    [
        html.H4("AWARE Threats Over Time",
                style={
                    "paddingLeft": "20px",
                    "paddingTop": "5px"
                }),
        dcc.Graph(id="atot-graph",
                  figure=generate_aware_threats_over_time_graph()),
    ],
    style={
        "marginBottom": "30px",
        "marginTop": "30px",
        "boxShadow": "0 4px 6px 0 rgba(0, 0, 0, 0.5)",
    })

threat_locations_map = html.Div(
    [
        html.H4("Threat Locations",
                style={
                    "paddingLeft": "20px",
                    "paddingTop": "5px"
                }),
        dcc.Graph(id="tl-map", figure=generate_threat_locations_map()),
    ],
    style={
        "marginBottom": "30px",
        "marginTop": "30px",
        "boxShadow": "0 4px 6px 0 rgba(0, 0, 0, 0.5)",
    })

events_details_graph = html.Div(
    [
        html.H4("Blocked Events",
                style={
                    "paddingLeft": "20px",
                    "paddingTop": "5px"
                }),
        generate_events_details_table(),
    ],
    style={
        "marginBottom": "30px",
        "marginTop": "30px",
        "boxShadow": "0 4px 6px 0 rgba(0, 0, 0, 0.5)",
    })

# Card flexbox containers
vis_1 = html.Div(dbc.Container(
    [
        html.Div(threat_risk_score_graph, className="graph-container"),
        html.Div(threat_priorities_graph, className="graph-container"),
    ],
    style={
        "display": "flex",
        "flexWrap": "wrap",
        "justifyContent": "space-between",
        "rowGap": "10px",
    }),
                 style={
                     "marginRight": "30px",
                     "marginLeft": "30px",
                     "padding": "10px",
                     "flexWrap": "wrap",
                 })

vis_2 = html.Div(dbc.Container(
    [
        html.Div(threat_source_graph, className="graph-container"),
        html.Div(threat_destination_graph, className="graph-container"),
    ],
    style={
        "display": "flex",
        "flexWrap": "wrap",
        "justifyContent": "space-between",
        "rowGap": "10px",
    }),
                 style={
                     "marginRight": "30px",
                     "marginLeft": "30px",
                     "padding": "10px",
                     "flexWrap": "wrap",
                 })

vis_3 = html.Div(dbc.Container(
    [
        html.Div(aware_threats_over_time_graph, className="graph-container"),
    ],
    style={
        "display": "flex",
        "flexWrap": "wrap",
        "justifyContent": "space-between",
        "rowGap": "10px",
    }),
                 style={
                     "marginRight": "30px",
                     "marginLeft": "30px",
                     "padding": "10px",
                     "flexWrap": "wrap",
                 })

vis_4 = html.Div(dbc.Container(
    [
        html.Div(threat_locations_map, className="graph-container"),
    ],
    style={
        "display": "flex",
        "flexWrap": "wrap",
        "justifyContent": "space-between",
        "rowGap": "10px",
    }),
                 style={
                     "marginRight": "30px",
                     "marginLeft": "30px",
                     "padding": "10px",
                     "flexWrap": "wrap",
                 })

vis_5 = html.Div(dbc.Container(
    [
        html.Div(events_details_graph, className="graph-container"),
    ],
    style={
        "display": "flex",
        "flexWrap": "wrap",
        "justifyContent": "space-between",
        "rowGap": "10px",
    }),
                 style={
                     "marginRight": "30px",
                     "marginLeft": "30px",
                     "padding": "10px",
                     "flexWrap": "wrap",
                 })

# Callbacks


@app.callback(  # type: ignore
    Output("navbar-collapse", "is_open"),
    [Input("navbar-toggler", "n_clicks")],
    [State("navbar-collapse", "is_open")],
)
def toggle_navbar_collapse(n: int, is_open: bool) -> bool:
    """Toggles the state of the navigation bar collapse on small screens.

    This callback function is triggered by clicking the navbar toggler button.
    It changes the state of the navbar (open or closed) based on its current
    state. This function is particularly useful for responsive designs where
    screen real estate is limited.

    Args:
        n (int): The number of times the navbar toggler has been clicked. It
          serves as a trigger for the callback.
        is_open (bool): The current state of the navbar collapse (True if
          open, False if closed).

    Returns:
        The new state of the navbar collapse (True to open it, False
          to close it).

    Note:
    - This function is designed to be used as a callback in a Dash application,
        requiring the @app.callback decorator to bind it to specific components
        and events.
    """
    if n:
        return not is_open
    return is_open


@app.callback(  # type: ignore
    Output("table-sorting-filtering", "data"),
    Input("table-sorting-filtering", "page_current"),
    Input("table-sorting-filtering", "page_size"),
    Input("table-sorting-filtering", "sort_by"),
    Input("table-sorting-filtering", "filter_query"))
def update_table(page_current: int, page_size: int, sort_by: list[dict[str,
                                                                       str]],
                 t_filter: str) -> list[dict[Hashable, Any]]:
    """Updates the data displayed in the datatable based on pagination,
    sorting, and filtering parameters.

    This callback function fetches and processes data for display in a Dash
    datatable component, considering the current page, the number of records
    per page, sorting criteria, and any filters applied by the user. The
    function utilizes an external `filter_logic` function to perform the
    actual data filtering and sorting logic.

    Args:
        page_current (int): The current page number in the datatable
          pagination.
        page_size (int): The number of records to display per page in the
          datatable.
        sort_by (list[dict[str, str]]): A list of dictionaries specifying how
          the data should be sorted. Each dictionary should contain the column
          ID to sort by ('column_id') and the direction ('asc' or 'desc').
        t_filter (str): A filter query string specifying how the data should
          be filtered.

    Returns:
        A list of dictionaries representing the filtered and sorted data to be
          displayed on the current page of the datatable.

    Note:
    - This function is intended to be used as a callback in a Dash application,
        and it relies on the `filter_logic` function to handle the specifics of
        data processing based on the provided parameters."""
    return filter_logic(page_current, page_size, sort_by, t_filter)


# Application layout

app.layout = html.Div(id="main-layout",
                      children=[
                          navbar,
                          title,
                          vis_1,
                          vis_2,
                          vis_3,
                          vis_4,
                          vis_5,
                      ])

# Running the server
if __name__ == "__main__":
    app.run_server(debug=True, port=8050, host="0.0.0.0")
