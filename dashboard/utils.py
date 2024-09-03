"""utils.py"""

from __future__ import annotations
from typing import Hashable, Any
import pathlib
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from dash import dash_table

# Define APP_PATH as the absolute path of the directory containing this script.
APP_PATH = str(pathlib.Path(__file__).parent.resolve())

# Open and read the JSON file containing event data into a pandas DataFrame.
# The JSON file is expected to be located in a 'data' subdirectory of APP_PATH.
try:
    with open(f"{APP_PATH}/data/events.json", encoding="utf-8") as f:
        json_data = pd.read_json(f)
except FileNotFoundError:
    json_data = pd.DataFrame({
        "AWARE Threats": {
            "Count": [],
            "Date": []
        },
        "Priorities": {
            "Count": [0, 0, 0, 0, 0, 0],
            "Priority": ["5", "4", "3", "2", "1", "0"]
        },
        "Threat Destinations": {
            "Count": [],
            "Destination": []
        },
        "Threat Sources": {
            "Count": [],
            "Source": []
        }
    })


def calculate_score(priorites_dict: dict[str, int]) -> float:
    """Calculates a weighted score based on predefined scoring and
    normalization calculations.

    The function first filters a given dictionary of priorities for specific
    keys ("0", "1", "2", "3"), calculates the total of values associated with
    these priorities, and then computes a weighted score using custom scoring
    and normalization factors. The scoring factors are adjusted based on the
    total of priorities, with special treatment for the "0" priority. The final
    score is the sum of the product of values from the input dictionary and
    their corresponding scoring factors, divided by the sum of the product of
    the values and their corresponding normalization factors.

    Args:
        priorites_dict (dict[str, int]): A dictionary where keys represent
          priority levels as strings ("0", "1", "2", "3") and values represent
          counts or quantities associated with these priorities.

    Returns:
        The calculated weighted score, rounded to three decimal places. If the
          normalization factor (n_value) is zero, preventing division, the
          function returns 0.0 as a default.

    Note:
    - The function uses a combination of `filter`, `map`, and `sum` to perform
        calculations in a functional style.
    - The score calculation is specifically tailored to the use case and
        expects the input dictionary keys to match the defined priorities.
        Keys outside the defined priorities ("0", "1", "2", "3") are ignored
        in the calculation.
    """
    priorities = {"0", "1", "2", "3"}
    priotities_total = sum(
        map(lambda kv: kv[1],
            filter(lambda kv: kv[0] in priorities, priorites_dict.items())))

    scoring_calc = {
        "0": float(priotities_total * -.1),
        "1": 0.25,
        "2": 0.50,
        "3": 0.95
    }
    n_calc = {"0": float(priotities_total), "1": 25.0, "2": 1.10, "3": 0.95}

    total_value = sum(
        map(lambda kv: scoring_calc[kv[0]] * kv[1],
            filter(lambda kv: kv[0] in scoring_calc, priorites_dict.items())))
    n_value = sum(
        map(lambda kv: n_calc[kv[0]] * kv[1],
            filter(lambda kv: kv[0] in n_calc, priorites_dict.items())))
    thread_risk_score = (total_value / n_value) if n_value else 0.0

    return round(thread_risk_score, 3) if thread_risk_score >= 0.0 else round(
        0.0, 3)


def generate_threat_risk_score_graph() -> go.Figure:
    """Generates a donut chart visualizing the threat risk score and its
    distribution across predefined risk categories.

    This function calculates the overall threat risk score based on priority
    counts sourced from a global 'json_data' dictionary. The risk score is
    visually represented in the center of the donut chart, with the chart
    itself illustrating the score proportion against the remainder to a full
    score. Additionally, a legend next to the donut chart depicts various
    risk levels for contextual emphasis.

    The function dynamically assigns a color to the score segment of the
    chart based on the calculated score's value, ranging from "royalblue"
    (low risk) to "darkred" (high risk).

    Returns:
        A Plotly Figure object containing the configured donut chart. The
          figure includes an annotated threat risk score, a color-coded
          representation of the score, and a legend delineating various
          risk levels without corresponding values, serving purely as
          a visual aid.

    Note:
    - The 'json_data' global variable must be pre-defined and structured to
        include necessary information under "Priorities" for this function
        to operate correctly.
    - The function depends on the 'calculate_score' function to compute the
        threat risk score from priority counts.
    - Risk levels and their color representation are predefined within the
        function.
    - The chart is designed to suppress legends and hover information for
        clarity and focuses solely on the visual representation of the threat
        risk score.
    """
    priorities = dict(
        zip(json_data["Priorities"]["Priority"],
            json_data["Priorities"]["Count"]))

    score = calculate_score(priorities)
    remainder = 1 - score
    score_color = "gainsboro"

    if score <= 0.250:
        score_color = "darkred"
    elif 0.250 < score <= 0.400:
        score_color = "red"
    elif 0.400 < score <= 0.500:
        score_color = "orangered"
    elif 0.500 < score <= 0.600:
        score_color = "orange"
    elif 0.600 < score <= 0.700:
        score_color = "yellow"
    elif 0.700 < score <= 0.800:
        score_color = "limegreen"
    elif 0.800 < score <= 0.900:
        score_color = "turquoise"
    elif 0.900 < score:
        score_color = "royalblue"
    else:
        pass

    trs_df = pd.DataFrame({
        "Label": ["Score", "Remainder", "High Risk", "Low Risk"],
        "Value": [score, remainder, 0, 0]
    })

    fig = go.Figure(data=[
        go.Pie(
            labels=trs_df["Label"],
            values=trs_df["Value"],
            hole=.7,
            textinfo="none",
            showlegend=False,
            hoverinfo="skip",
            sort=False,
            marker={
                "colors": [score_color, "gainsboro"],
                "line": {
                    "color": "gainsboro",
                    "width": 1
                }
            },
        )
    ])
    fig.add_trace(
        go.Pie(
            labels=[
                "Major Risk", "Major Risk ", "Major Risk  ", "Cautionary Risk",
                "Minor Risk", "Acceptable Risk", "Acceptable Risk ",
                "Acceptable Risk  "
            ],
            values=[1, 1, 1, 1, 1, 1, 1, 1],
            hole=1,
            textinfo="none",
            hoverinfo="skip",
            sort=False,
            marker={
                "colors": [
                    "darkred", "red", "orangered", "orange", "yellow",
                    "limegreen", "turquoise", "royalblue"
                ]
            },
        ))
    fig.add_annotation(x=0.5,
                       y=0.5,
                       text=f"<b>{score:4.3f}</b>",
                       showarrow=False,
                       arrowhead=1,
                       font_size=40,
                       font={
                           "color": score_color,
                       })

    fig.update_layout(margin={"l": 30, "r": 30, "t": 30, "b": 30})
    return fig


def generate_threat_priorites_graph() -> go.Figure:
    """Generates a horizontal bar graph representing the distribution of
    threat priorities.

    This function creates a horizontal bar graph that visualizes the counts of
    different threat priorities based on data extracted from a global
    'json_data' dictionary. The graph displays the four highest priorities
    (or fewer if less data is available), with custom colors assigned to each
    priority level for clear distinction.

    The priorities are expected to be provided within the 'json_data' under
    "Priorities", including both "Priority" (as category labels) and "Count"
    (as the number of occurrences for each priority). The color scheme for
    the priorities is predefined, with specific colors representing various
    levels of threat.

    Returns:
        A Plotly Figure object containing the configured horizontal bar graph.
          The graph emphasizes the distribution of threat priorities by count,
          with customization options applied for visual clarity, including
          colored bars based on priority level and suppressed y-axis labels
          for a cleaner presentation.

    Note:
    - The 'json_data' global variable must be pre-defined and structured
        correctly with "Priorities" data for the function to execute
        successfully.
    - The graph displays data for the four highest priorities by default, as
        extracted from the tail end of the sorted 'tp_df' DataFrame.
    - The function utilizes Plotly's graphing library to create the
        visualization, applying a set of custom styling rules to enhance
        readability and visual appeal.

    Example Usage:
        To use this function, ensure 'json_data' contains the required
        "Priorities" structure with "Priority" and "Count" fields. Then,
        simply call the function to generate the graph, which can then be
        rendered in a Dash application or a standalone Plotly plot.
    """
    tp_df = pd.DataFrame({
        "Priority": json_data["Priorities"]["Priority"],
        "Count": json_data["Priorities"]["Count"]
    })
    priority_colors = {
        "0": "red",
        "1": "orange",
        "2": "yellow",
        "3": "limegreen",
        "4": "limegreen",
        "5": "limegreen"
    }

    fig = go.Figure()
    for _, row in tp_df.tail(4).iterrows():
        color = priority_colors.get(row["Priority"], "limegreen")
        fig.add_trace(
            go.Bar(
                x=[row["Count"]],
                y=[row["Priority"]],
                orientation="h",
                marker={"color": color},
                name=f"Priority {row['Priority']}",
            ))
    fig.update_xaxes(title_text="Total Number of Events")
    fig.update_layout(legend={"traceorder": "reversed"})
    fig.update_layout(margin={"l": 30, "r": 30, "t": 30, "b": 30})
    fig.update_yaxes(visible=False)
    return fig


def generate_threat_source_graph() -> go.Figure:
    """Generates a Plotly graph object (Figure) representing the distribution
    of threat sources.

    This function creates a pie chart that visualizes the count of threats
    originating from various sources. The data for the graph is expected to
    be provided by a global 'json_data' variable, specifically from the
    "Threat Sources" section, which should include "Source" and "Count" lists.

    Returns:
        A Plotly Figure object containing a pie chart with the threat sources
          distribution. The pie chart is styled with a hole in the center, no
          text information on slices, and a custom color scheme. Margins are
          also set for a cleaner layout.

    Note:
    - This function relies on the global variable 'json_data' being predefined
        and structured with the necessary data for "Threat Sources".
    - The colors for the pie chart are defined using Plotly Express's
        qualitative Light24_r color scale for visual distinction.
    """
    ts_df = pd.DataFrame({
        "Source": json_data["Threat Sources"]["Source"],
        "Count": json_data["Threat Sources"]["Count"]
    })

    fig = go.Figure(data=[
        go.Pie(
            labels=ts_df["Source"],
            values=ts_df["Count"],
            hole=.7,
            textinfo="none",
            marker={
                "colors": px.colors.qualitative.Light24_r,
                "line": {
                    "color": "black",
                    "width": 1
                }
            },
        )
    ])
    fig.update_layout(margin={"l": 30, "r": 30, "t": 30, "b": 30})
    return fig


def generate_threat_destination_graph() -> go.Figure:
    """Generates a Plotly graph object (Figure) representing the distribution
    of threat destinations.

    This function creates a pie chart that visualizes the count of threats
    associated with various destinations. The data for the graph is sourced
    from a global 'json_data' variable, specifically from the
    "Threat Destinations" section, which should include "Destination" and
    "Count" lists.

    Returns:
        A Plotly Figure object containing a pie chart with the distribution
          of threat destinations. The chart is designed with a hole in the
          center, no text information on the slices, and utilizes a custom
          color scheme. Layout margins are adjusted for a cleaner
          visual presentation.

    Note:
    - The function assumes 'json_data' is a global variable previously defined
        and correctly structured to include the required information for
        "Threat Destinations".
    - The visualization uses Plotly Express's qualitative Dark24 color scale
        to ensure slices are distinct and visually appealing.
    """
    td_df = pd.DataFrame({
        "Destination":
        json_data["Threat Destinations"]["Destination"],
        "Count":
        json_data["Threat Destinations"]["Count"]
    })

    fig = go.Figure(data=[
        go.Pie(
            labels=td_df["Destination"],
            values=td_df["Count"],
            hole=.7,
            textinfo="none",
            marker={
                "colors": px.colors.qualitative.Dark24,
                "line": {
                    "color": "black",
                    "width": 1
                }
            },
        )
    ])
    fig.update_layout(margin={"l": 30, "r": 30, "t": 30, "b": 30})
    return fig


def generate_aware_threats_over_time_graph() -> go.Figure:
    """Generates a Plotly graph object representing AWARE threats over time.

    This function creates a time series scatter plot, where the x-axis
    represents timestamps at 12-hour intervals, and the y-axis represents the
    number of AWARE threat events recorded at each timestamp. The data for
    plotting is extracted from a global 'json_data' dictionary, specifically
    from the "AWARE Threats" section, which should include both "Date" and
    "Count" lists.

    Note:
    - This function relies on the global variable 'json_data' being predefined
        and properly structured with the necessary data.
    - The function assumes that 'json_data["AWARE Threats"]["Date"]' contains
        datetime objects or strings that can be interpreted as dates, and
        'json_data["AWARE Threats"]["Count"]' contains integer or float values
        representing the event counts.

    Returns:
        A Plotly Figure object containing the configured scatter plot,
          ready to be rendered or further customized.

    Example of expected 'json_data' structure:
        json_data = {
            "AWARE Threats": {
                "Date": ["2023-01-01 00:00", "2023-01-01 12:00", ...],
                "Count": [10, 15, ...]
            }
        }
    """
    atot_df = pd.DataFrame({
        "Date": json_data["AWARE Threats"]["Date"],
        "Count": json_data["AWARE Threats"]["Count"]
    })

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(x=atot_df["Date"],
                   y=atot_df["Count"],
                   mode="lines",
                   name="Events"))
    fig.update_yaxes(title_text="Number of Events")
    fig.update_xaxes(title_text="Timestamp per 12 Hours")

    fig.update_layout(margin={"l": 30, "r": 30, "t": 30, "b": 30})
    return fig


def generate_threat_locations_map() -> go.Figure:
    """Generates a geographic scatter plot visualizing threat locations and
    their counts.

    This function reads threat location data from a CSV file and visualizes it
    on a world map. Each location's size on the map corresponds to its threat
    count, categorized into ranges that are represented with different colors.
    The function dynamically calculates these ranges based on the maximum
    threat count found in the data, ensuring an even distribution across
    predefined color categories.

    Returns:
        A Plotly Figure object containing a Scattergeo plot. The plot includes
        markers for each threat location, sized according to the threat count
        and colored by defined count ranges. The map provides visual insights
        into the distribution and intensity of threats across different
        geographical locations.

    Note:
    - The CSV file should be located in the 'data' subdirectory of the
        APP_PATH directory.
    - The CSV file must contain at least 'City Name', 'Country Name','Count',
        'Lon', and 'Lat' columns.
    - The 'Count' column is used to size and color the markers on the map,
        with the size being proportional to the threat count and the color
        indicating the threat count range.
    - Color categories are predefined and range from yellow (lowest counts)
        to darkred (highest counts), with each category representing an equal
        portion of the range of counts present in the data.
    - The function assumes the presence of a global variable 'APP_PATH' that
        specifies the base directory path for locating the CSV file.
    """
    try:
        tl_df = pd.read_csv(f"{APP_PATH}/data/locations.csv")
    except FileNotFoundError:
        tl_df = pd.DataFrame({
            "City Name": [""],
            "Country Name": [""],
            "Count": [0],
            "Lat": [0.0],
            "Lon": [0.0]
        })

    tl_df["text"] = tl_df["City Name"] + ", " + tl_df[
        "Country Name"] + "<br>Count: " + (tl_df["Count"]).astype(str)
    colors = ["yellow", "orange", "orangered", "red", "darkred"]
    max_count = max(tl_df["Count"])
    step = max_count // len(colors)
    limits = [(i * step + 1,
               (i + 1) * step if i < len(colors) - 1 else max_count)
              for i in range(len(colors))]
    scale = 2500

    fig = go.Figure()
    for c, lim in enumerate(limits):
        tl_df_sub = tl_df[(tl_df['Count'] >= lim[0])
                          & (tl_df['Count'] <= lim[1])]
        fig.add_trace(
            go.Scattergeo(locationmode="ISO-3",
                          lon=tl_df_sub["Lon"],
                          lat=tl_df_sub["Lat"],
                          text=tl_df_sub["text"],
                          marker={
                              "size": tl_df_sub["Count"] / scale,
                              "color": colors[c],
                              "line_color": "rgb(40, 40, 40)",
                              "line_width": 0.5,
                              "sizemode": "area",
                          },
                          name=f"{lim[0]} - {lim[1]}"))

    fig.update_layout(
        showlegend=True,
        legend_title="Count",
        geo={
            "scope": "world",
            "showcountries": True,
            "showsubunits": True,
            "landcolor": "rgb(30, 30, 30)"
        },
    )
    fig.update_layout(margin={"l": 30, "r": 30, "t": 30, "b": 30})
    return fig


def generate_events_details_table() -> dash_table.DataTable:
    """Generates a Dash DataTable for displaying event details.

    This function creates and configures a DataTable component for use in a
    Dash application, designed to display details about events. The table
    includes columns for date/time, source IP address, destination IP
    address, event description, and priority. Each column is made deletable,
    allowing users to customize their view of the table. Pagination,
    filtering, and sorting are set to custom behaviors, which should be
    implemented separately in the Dash app callbacks.

    The styling of the table is configured for a dark theme, with specific
    colors for headers, filters, and data rows, as well as a fixed maximum
    width and horizontal scrolling.

    Returns:
        A Dash DataTable component configured with columns for event details,
          custom pagination, filtering, and sorting actions, and styled for
          a dark theme.

    Example Usage:
        To use this function, simply call it to generate the table component
          and include the returned component in the layout of your Dash app.
          Note that implementing the functionality for custom actions
          (pagination, filtering, sorting) requires additional callbacks in
          your Dash app.
    """
    fig = dash_table.DataTable(
        id="table-sorting-filtering",
        # columns=[{
        #     "name": i,
        #     "id": i,
        #     "deletable": True
        # } for i in df.columns],
        columns=[{
            "name": "Date/TIme",
            "id": "Date/Time",
            "deletable": True
        }, {
            "name": "Source IP Address",
            "id": "Source IP Address",
            "deletable": True
        }, {
            "name": "Destination IP Address",
            "id": "Destination IP Address",
            "deletable": True
        }, {
            "name": "Event Description",
            "id": "Event Description",
            "deletable": True
        }, {
            "name": "Priority",
            "id": "Priority",
            "deletable": True
        }],
        page_current=0,
        page_size=15,
        page_action="custom",
        filter_action="custom",
        filter_query="",
        sort_action="custom",
        sort_mode="multi",
        sort_by=[],
        style_header={
            "backgroundColor": "rgb(50, 50, 50)",
            "color": "white",
            "border": "2px solid black",
        },
        style_filter={
            "backgroundColor": "rgb(40, 40, 40)",
            "border": "2px solid black",
        },
        style_data={
            "backgroundColor": "rgb(30, 30, 30)",
            "color": "white",
            "border": "1px solid black",
        },
        style_table={
            "maxWidth": "100%",
            "overflowX": "auto"
        },
    )
    return fig


# Event Details datatable filtering


def split_filter_part(filter_part: str) -> tuple[str, str, str] | list[None]:
    """Splits a filter string into its constituent parts: the column name,
    operator, and value.

    This function parses a string containing a filtering expression,
    identifying the operation (e.g., greater than, contains) and the
    value to apply the operation with. It supports a predefined set of
    operations such as comparison and containment checks.

    Args:
        filter_part (str): The filter expression string to be parsed.

    Returns:
        A tuple containing the column name, the operation as a string,
          and the value as a string. If the filter_part cannot be parsed,
          returns a list containing three None values.
    """
    operators = [["ge ", ">="], ["le ", "<="], ["lt ", "<"], ["gt ", ">"],
                 ["ne ", "!="], ["eq ", "="], ["contains "],
                 ["datestartswith "]]

    value: str | float
    for operator_type in operators:
        for operator in operator_type:
            if operator in filter_part:
                name_part, value_part = filter_part.split(operator, 1)
                name = name_part[name_part.find("{") + 1:name_part.rfind("}")]
                value_part = value_part.strip()
                v0 = value_part[0]
                if (v0 == value_part[-1] and v0 in ("'", '"', '`')):
                    value = value_part[1:-1].replace("\\" + v0, v0)
                else:
                    try:
                        value = str(value_part)
                    except ValueError:
                        value = value_part
                return name, operator_type[0].strip(), value

    return [None] * 3


def filter_logic(page_current: int, page_size: int, sort_by: list[dict[str,
                                                                       str]],
                 t_filter: str) -> list[dict[Hashable, Any]]:
    """Applies filtering and sorting logic to a dataset based on the provided
    criteria, returning the filtered and sorted dataset as a list of
    dictionaries for a specified page of results.

    This function reads data from a CSV file, applies filtering based on a
    filter string, sorts the filtered results if sorting criteria are provided,
    and paginates the results based on the current page and page size
    parameters.

    Args:
        page_current (int): The current page number (0-indexed) for pagination.
        page_size (int): The number of records per page for pagination.
        sort_by (list[dict[str, str]]): A list of dictionaries specifying the
          sorting criteria. Each dictionary should have a 'column_id' key
          specifying the column to sort by and a 'direction' key specifying the
          sort direction ('asc' or 'desc').
        t_filter (str): The filter string containing all filtering expressions
          to be applied, joined by " && ".

    Returns:
        A list of dictionaries representing the paginated, filtered, and
          sorted records from the dataset. Each dictionary corresponds to a
          record in the dataset.
    """
    filtering_expressions = t_filter.split(" && ")
    columns = [
        "Date/Time", "Source IP Address", "Destination IP Address",
        "Event Description", "Priority"
    ]
    dtypes = {
        "Date/Time": str,
        "Source IP Address": str,
        "Destination IP Address": str,
        "Event Description": str,
        "Priority": int,
    }

    try:
        df = pd.read_csv(f"{str(APP_PATH)}/data/events.csv",
                         header=None,
                         encoding="utf-8",
                         names=columns,
                         dtype=dtypes)
        df.sort_values(by=["Date/Time"], inplace=True, ascending=False)
    except FileNotFoundError:
        df = pd.DataFrame()

    for filter_part in filtering_expressions:
        case_sensitive = "scontains" in filter_part
        col_name, operator, filter_value = split_filter_part(filter_part)
        if col_name and operator and filter_value:
            if operator in ("eq", "ne", "lt", "le", "gt", "ge"):
                df = df.loc[getattr(df[col_name], operator)(filter_value)]
            elif operator == "contains":
                if filter_value.isdigit():
                    df = df.loc[df[col_name].astype(str).str.contains(
                        filter_value)]
                else:
                    df = df.loc[df[col_name].str.contains(filter_value,
                                                          case=case_sensitive)]
            elif operator == "datestartswith":
                df = df.loc[df[col_name].str.startswith(filter_value)]

    if len(sort_by):
        df = df.sort_values(
            [col["column_id"] for col in sort_by],
            ascending=[col["direction"] == "asc" for col in sort_by],
            inplace=False)

    page = page_current
    size = page_size
    return df.iloc[page * size:(page + 1) * size].to_dict("records")
