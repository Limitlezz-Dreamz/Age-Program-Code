# Volume Engulfing Trading Indicator

A sophisticated trading indicator that detects engulfing candle patterns with volume confirmation. This indicator helps identify potential reversal points in financial markets by combining traditional candlestick pattern analysis with volume analysis.

## Features

- **Engulfing Pattern Detection**: Identifies both bullish and bearish engulfing patterns
- **Volume Confirmation**: Only signals when volume exceeds configurable thresholds
- **Signal Strength Calculation**: Rates signal quality based on volume and pattern size
- **Flexible Parameters**: Customizable thresholds for different trading styles
- **Visualization**: Built-in plotting with candlestick charts and volume bars
- **Backtesting Support**: Tools for analyzing historical performance

## How It Works

### Engulfing Patterns

**Bullish Engulfing:**
- Previous candle is bearish (red)
- Current candle is bullish (green) 
- Current candle's body completely engulfs the previous candle's body
- Higher than average volume confirms the pattern

**Bearish Engulfing:**
- Previous candle is bullish (green)
- Current candle is bearish (red)
- Current candle's body completely engulfs the previous candle's body  
- Higher than average volume confirms the pattern

### Volume Analysis

The indicator calculates volume ratios compared to a rolling average and only generates signals when volume exceeds the specified threshold (default 1.5x average).

### Signal Strength

Signal strength (0-1) is calculated based on:
- Volume ratio (60% weight)
- Size of engulfment (40% weight)

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Import the indicator:
```python
from volume_engulfing_indicator import VolumeEngulfingIndicator, create_sample_data
```

## Quick Start

```python
import pandas as pd
from volume_engulfing_indicator import VolumeEngulfingIndicator, create_sample_data

# Create sample data or load your own OHLCV data
data = create_sample_data(100)

# Initialize the indicator
indicator = VolumeEngulfingIndicator(
    volume_threshold=1.5,    # Require 1.5x average volume
    volume_lookback=20,      # 20-period average for volume
    min_body_ratio=0.3,      # Minimum 30% body size
    min_engulfing_ratio=1.1  # 10% minimum engulfment
)

# Detect signals
signals = indicator.detect_signals(data)

# Print results
for signal in signals:
    print(f"{signal.type.value} signal at index {signal.index}")
    print(f"Volume: {signal.volume_ratio:.2f}x, Strength: {signal.strength:.2f}")
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `volume_threshold` | 1.5 | Minimum volume ratio vs average |
| `volume_lookback` | 20 | Periods for volume average calculation |
| `min_body_ratio` | 0.3 | Minimum body size as % of candle range |
| `min_engulfing_ratio` | 1.1 | Minimum engulfment size ratio |

## Data Format

Your data must be a pandas DataFrame with these columns:
- `open`: Opening price
- `high`: High price  
- `low`: Low price
- `close`: Closing price
- `volume`: Trading volume

## Example Configurations

### Conservative (Higher Quality, Fewer Signals)
```python
conservative = VolumeEngulfingIndicator(
    volume_threshold=2.0,     # Require 2x volume
    volume_lookback=30,       # Longer volume average
    min_body_ratio=0.5,       # Larger bodies required
    min_engulfing_ratio=1.5   # Significant engulfment
)
```

### Aggressive (More Signals, Lower Quality Filter)
```python
aggressive = VolumeEngulfingIndicator(
    volume_threshold=1.2,     # Lower volume requirement  
    volume_lookback=10,       # Shorter volume average
    min_body_ratio=0.2,       # Smaller bodies allowed
    min_engulfing_ratio=1.05  # Minimal engulfment
)
```

## Visualization

Create candlestick charts with signals marked:

```python
# Plot the signals
fig = indicator.plot_signals(data, start_idx=0, end_idx=100)
plt.show()

# Or save to file
plt.savefig('signals.png', dpi=300, bbox_inches='tight')
```

## Using with Real Market Data

### With yfinance
```python
import yfinance as yf

# Download data
ticker = "AAPL"
data = yf.download(ticker, period="6mo", interval="1d")

# Rename columns to match expected format
data = data.rename(columns={
    'Open': 'open',
    'High': 'high',
    'Low': 'low', 
    'Close': 'close',
    'Volume': 'volume'
})

# Use the indicator
indicator = VolumeEngulfingIndicator()
signals = indicator.detect_signals(data)
```

### With CSV Data
```python
# Load from CSV
data = pd.read_csv('your_data.csv')
# Ensure column names match: open, high, low, close, volume

signals = indicator.detect_signals(data)
```

## Output Methods

### Signal Objects
```python
signals = indicator.detect_signals(data)
for signal in signals:
    print(f"Type: {signal.type.value}")
    print(f"Index: {signal.index}")
    print(f"Volume Ratio: {signal.volume_ratio:.2f}")
    print(f"Strength: {signal.strength:.2f}")
```

### Enhanced DataFrame
```python
# Add signal columns to your data
data_with_signals = indicator.add_signals_to_dataframe(data)

# New columns added:
# - engulfing_signal: 1 (bullish), -1 (bearish), 0 (none)
# - signal_strength: 0.0 to 1.0
# - volume_ratio: ratio vs average volume
```

## Files

- `volume_engulfing_indicator.py`: Main indicator class
- `example_usage.py`: Comprehensive examples and demonstrations
- `requirements.txt`: Required Python packages
- `README.md`: This documentation

## Examples

Run the example script to see various use cases:

```bash
python3 example_usage.py
```

This will demonstrate:
- Basic usage
- Parameter customization
- Data analysis
- Simple backtesting
- Visualization
- Real data integration template

## Trading Notes

**⚠️ Important Disclaimers:**
- This is a technical analysis tool, not investment advice
- Always combine with other indicators and risk management
- Test thoroughly with historical data before live trading
- Consider market conditions and fundamentals
- Past performance doesn't guarantee future results

**Best Practices:**
- Use appropriate position sizing
- Set stop losses and take profits
- Consider the overall market trend
- Validate signals with other technical indicators
- Practice proper risk management

## License

This project is provided as-is for educational and research purposes.

## Contributing

Feel free to submit issues, suggestions, or improvements to enhance the indicator's functionality.