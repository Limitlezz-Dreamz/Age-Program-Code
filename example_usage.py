#!/usr/bin/env python3
"""
Example usage of the Volume Engulfing Indicator

This script demonstrates various ways to use the indicator:
1. Basic usage with sample data
2. Custom parameter configurations
3. Loading real data (placeholder for actual data source)
4. Visualization examples
5. Backtesting simulation
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from volume_engulfing_indicator import VolumeEngulfingIndicator, create_sample_data, EngulfingType


def example_basic_usage():
    """Basic example of using the volume engulfing indicator"""
    print("=" * 60)
    print("BASIC USAGE EXAMPLE")
    print("=" * 60)
    
    # Create sample data
    data = create_sample_data(150, seed=123)
    
    # Initialize indicator with default parameters
    indicator = VolumeEngulfingIndicator()
    
    # Detect signals
    signals = indicator.detect_signals(data)
    
    print(f"Total periods analyzed: {len(data)}")
    print(f"Engulfing signals found: {len(signals)}")
    print(f"Bullish signals: {sum(1 for s in signals if s.type == EngulfingType.BULLISH)}")
    print(f"Bearish signals: {sum(1 for s in signals if s.type == EngulfingType.BEARISH)}")
    print()
    
    # Show first few signals
    print("First 3 signals:")
    for i, signal in enumerate(signals[:3], 1):
        print(f"{i}. {signal.type.value.title()} at index {signal.index}")
        print(f"   Volume ratio: {signal.volume_ratio:.2f}x")
        print(f"   Signal strength: {signal.strength:.2f}")
        print()


def example_custom_parameters():
    """Example with different parameter configurations"""
    print("=" * 60)
    print("CUSTOM PARAMETERS EXAMPLE")
    print("=" * 60)
    
    data = create_sample_data(100, seed=456)
    
    # Conservative settings (fewer, higher quality signals)
    conservative_indicator = VolumeEngulfingIndicator(
        volume_threshold=2.0,      # Require 2x average volume
        volume_lookback=30,        # Longer lookback for volume average
        min_body_ratio=0.5,        # Larger body requirement
        min_engulfing_ratio=1.5    # More significant engulfment
    )
    
    # Aggressive settings (more signals, potentially lower quality)
    aggressive_indicator = VolumeEngulfingIndicator(
        volume_threshold=1.2,      # Lower volume requirement
        volume_lookback=10,        # Shorter lookback
        min_body_ratio=0.2,        # Smaller body requirement
        min_engulfing_ratio=1.05   # Minimal engulfment
    )
    
    conservative_signals = conservative_indicator.detect_signals(data)
    aggressive_signals = aggressive_indicator.detect_signals(data)
    
    print(f"Data periods: {len(data)}")
    print(f"Conservative signals: {len(conservative_signals)}")
    print(f"Aggressive signals: {len(aggressive_signals)}")
    print()
    
    print("Conservative vs Aggressive signal strength comparison:")
    if conservative_signals:
        avg_conservative_strength = np.mean([s.strength for s in conservative_signals])
        print(f"Average conservative strength: {avg_conservative_strength:.3f}")
    
    if aggressive_signals:
        avg_aggressive_strength = np.mean([s.strength for s in aggressive_signals])
        print(f"Average aggressive strength: {avg_aggressive_strength:.3f}")
    
    print()


def example_data_analysis():
    """Example of analyzing signals and adding to dataframe"""
    print("=" * 60)
    print("DATA ANALYSIS EXAMPLE")
    print("=" * 60)
    
    data = create_sample_data(200, seed=789)
    indicator = VolumeEngulfingIndicator(volume_threshold=1.6)
    
    # Add signals to dataframe
    data_with_signals = indicator.add_signals_to_dataframe(data)
    
    # Analyze the results
    total_signals = len(data_with_signals[data_with_signals['engulfing_signal'] != 0])
    bullish_signals = len(data_with_signals[data_with_signals['engulfing_signal'] == 1])
    bearish_signals = len(data_with_signals[data_with_signals['engulfing_signal'] == -1])
    
    print(f"Total signals: {total_signals}")
    print(f"Bullish: {bullish_signals} ({bullish_signals/total_signals*100:.1f}%)")
    print(f"Bearish: {bearish_signals} ({bearish_signals/total_signals*100:.1f}%)")
    print()
    
    # Show statistics for signals
    signal_data = data_with_signals[data_with_signals['engulfing_signal'] != 0]
    if len(signal_data) > 0:
        print("Signal Statistics:")
        print(f"Average signal strength: {signal_data['signal_strength'].mean():.3f}")
        print(f"Average volume ratio: {signal_data['volume_ratio'].mean():.2f}x")
        print(f"Max volume ratio: {signal_data['volume_ratio'].max():.2f}x")
        print()
        
        # Show top 5 strongest signals
        top_signals = signal_data.nlargest(5, 'signal_strength')
        print("Top 5 strongest signals:")
        for idx, row in top_signals.iterrows():
            signal_type = "Bullish" if row['engulfing_signal'] == 1 else "Bearish"
            print(f"  {signal_type} at index {idx}: strength={row['signal_strength']:.3f}, volume={row['volume_ratio']:.2f}x")
    
    print()


def example_backtesting_simulation():
    """Simple backtesting simulation example"""
    print("=" * 60)
    print("BACKTESTING SIMULATION EXAMPLE")
    print("=" * 60)
    
    # Generate more realistic data with trend
    np.random.seed(101)
    n_periods = 300
    
    # Create trending data
    trend = np.linspace(0, 0.3, n_periods)  # 30% upward trend over period
    noise = np.random.normal(0, 0.02, n_periods)
    price_changes = trend + noise
    
    # Add some volatility spikes for engulfing patterns
    for i in [50, 51, 100, 101, 150, 151, 200, 201, 250, 251]:
        if i < len(price_changes):
            price_changes[i] = np.random.choice([-0.08, 0.08])  # Random large moves
    
    # Build OHLCV data
    base_price = 100
    prices = [base_price]
    for change in price_changes:
        prices.append(prices[-1] * (1 + change))
    
    data = []
    for i in range(n_periods):
        open_price = prices[i]
        close_price = prices[i + 1]
        
        high_low_range = abs(close_price - open_price) * np.random.uniform(1.2, 2.5)
        high = max(open_price, close_price) + high_low_range * np.random.uniform(0, 0.3)
        low = min(open_price, close_price) - high_low_range * np.random.uniform(0, 0.3)
        
        base_volume = 15000
        volume_multiplier = 1 + abs(price_changes[i]) * 8
        volume = int(base_volume * volume_multiplier * np.random.uniform(0.7, 1.3))
        
        data.append({
            'open': open_price,
            'high': high,
            'low': low,
            'close': close_price,
            'volume': volume
        })
    
    df = pd.DataFrame(data)
    
    # Run indicator
    indicator = VolumeEngulfingIndicator(volume_threshold=1.4)
    signals = indicator.detect_signals(df)
    
    # Simple backtesting logic
    initial_capital = 10000
    position = 0  # 0 = no position, 1 = long, -1 = short
    capital = initial_capital
    trades = []
    
    for signal in signals:
        entry_price = df['close'].iloc[signal.index]
        
        if signal.type == EngulfingType.BULLISH and position <= 0:
            # Enter long position
            if position == -1:  # Close short first
                profit = (trades[-1]['entry_price'] - entry_price) * abs(position)
                capital += profit
                trades.append({
                    'type': 'close_short',
                    'index': signal.index,
                    'price': entry_price,
                    'profit': profit
                })
            
            position = 1
            trades.append({
                'type': 'long_entry',
                'index': signal.index,
                'entry_price': entry_price,
                'strength': signal.strength
            })
            
        elif signal.type == EngulfingType.BEARISH and position >= 0:
            # Enter short position
            if position == 1:  # Close long first
                profit = (entry_price - trades[-1]['entry_price']) * abs(position)
                capital += profit
                trades.append({
                    'type': 'close_long',
                    'index': signal.index,
                    'price': entry_price,
                    'profit': profit
                })
            
            position = -1
            trades.append({
                'type': 'short_entry',
                'index': signal.index,
                'entry_price': entry_price,
                'strength': signal.strength
            })
    
    # Close final position
    if position != 0:
        final_price = df['close'].iloc[-1]
        if position == 1:
            profit = (final_price - trades[-1]['entry_price']) * abs(position)
        else:
            profit = (trades[-1]['entry_price'] - final_price) * abs(position)
        capital += profit
        trades.append({
            'type': 'final_close',
            'index': len(df) - 1,
            'price': final_price,
            'profit': profit
        })
    
    # Results
    total_return = (capital - initial_capital) / initial_capital * 100
    profitable_trades = [t for t in trades if 'profit' in t and t['profit'] > 0]
    losing_trades = [t for t in trades if 'profit' in t and t['profit'] < 0]
    
    print(f"Initial capital: ${initial_capital:,.2f}")
    print(f"Final capital: ${capital:,.2f}")
    print(f"Total return: {total_return:.2f}%")
    print(f"Total signals: {len(signals)}")
    print(f"Total trades: {len([t for t in trades if 'profit' in t])}")
    print(f"Profitable trades: {len(profitable_trades)}")
    print(f"Losing trades: {len(losing_trades)}")
    
    if len(profitable_trades) + len(losing_trades) > 0:
        win_rate = len(profitable_trades) / (len(profitable_trades) + len(losing_trades)) * 100
        print(f"Win rate: {win_rate:.1f}%")
        
        if profitable_trades:
            avg_profit = np.mean([t['profit'] for t in profitable_trades])
            print(f"Average profit per winning trade: ${avg_profit:.2f}")
        
        if losing_trades:
            avg_loss = np.mean([t['profit'] for t in losing_trades])
            print(f"Average loss per losing trade: ${avg_loss:.2f}")
    
    print()


def example_visualization():
    """Example of creating visualizations"""
    print("=" * 60)
    print("VISUALIZATION EXAMPLE")
    print("=" * 60)
    
    # Create interesting sample data
    data = create_sample_data(80, seed=999)
    indicator = VolumeEngulfingIndicator(volume_threshold=1.3)
    
    # Create plot
    fig = indicator.plot_signals(data, start_idx=20, end_idx=70)
    
    # Save the plot
    plt.savefig('volume_engulfing_signals.png', dpi=300, bbox_inches='tight')
    print("Chart saved as 'volume_engulfing_signals.png'")
    
    # Don't show plot in automated environment
    # plt.show()
    plt.close()


def example_real_data_template():
    """Template for using real market data"""
    print("=" * 60)
    print("REAL DATA TEMPLATE")
    print("=" * 60)
    
    print("To use with real market data, replace this section with:")
    print("""
    # Example with yfinance (install with: pip install yfinance)
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
    
    # Visualize
    fig = indicator.plot_signals(data)
    plt.show()
    """)
    print()


if __name__ == "__main__":
    print("Volume Engulfing Indicator - Complete Examples")
    print("=" * 60)
    
    # Run all examples
    example_basic_usage()
    example_custom_parameters()
    example_data_analysis()
    example_backtesting_simulation()
    example_visualization()
    example_real_data_template()
    
    print("All examples completed!")
    print("\nNext steps:")
    print("1. Install requirements: pip install -r requirements.txt")
    print("2. Run this script: python example_usage.py")
    print("3. Modify parameters in volume_engulfing_indicator.py as needed")
    print("4. Use your own market data by following the real data template")