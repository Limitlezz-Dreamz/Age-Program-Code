import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from typing import Tuple, List, Optional
from dataclasses import dataclass
from enum import Enum


class EngulfingType(Enum):
    """Enum for different types of engulfing patterns"""
    BULLISH = "bullish"
    BEARISH = "bearish"
    NONE = "none"


@dataclass
class EngulfingSignal:
    """Data class to hold engulfing signal information"""
    index: int
    type: EngulfingType
    volume_ratio: float
    strength: float
    current_candle: dict
    previous_candle: dict


class VolumeEngulfingIndicator:
    """
    Trading indicator that detects engulfing candle patterns with volume confirmation.
    
    An engulfing pattern occurs when:
    1. The current candle's body completely engulfs the previous candle's body
    2. The pattern is confirmed by higher volume than the average
    3. The strength is measured by the volume ratio and price movement
    """
    
    def __init__(self, 
                 volume_threshold: float = 1.5,
                 volume_lookback: int = 20,
                 min_body_ratio: float = 0.3,
                 min_engulfing_ratio: float = 1.1):
        """
        Initialize the Volume Engulfing Indicator
        
        Args:
            volume_threshold: Minimum volume ratio compared to average (default 1.5x)
            volume_lookback: Period for calculating average volume (default 20)
            min_body_ratio: Minimum body size as ratio of total candle range (default 0.3)
            min_engulfing_ratio: Minimum ratio for engulfing (default 1.1x)
        """
        self.volume_threshold = volume_threshold
        self.volume_lookback = volume_lookback
        self.min_body_ratio = min_body_ratio
        self.min_engulfing_ratio = min_engulfing_ratio
        
    def _calculate_body_size(self, open_price: float, close_price: float) -> float:
        """Calculate the size of the candle body"""
        return abs(close_price - open_price)
    
    def _calculate_candle_range(self, high: float, low: float) -> float:
        """Calculate the total range of the candle"""
        return high - low
    
    def _is_valid_candle(self, candle: dict) -> bool:
        """Check if candle has sufficient body size"""
        body_size = self._calculate_body_size(candle['open'], candle['close'])
        candle_range = self._calculate_candle_range(candle['high'], candle['low'])
        
        if candle_range == 0:
            return False
            
        body_ratio = body_size / candle_range
        return body_ratio >= self.min_body_ratio
    
    def _is_bullish_engulfing(self, current: dict, previous: dict) -> bool:
        """
        Check if current candle forms a bullish engulfing pattern
        
        Conditions:
        1. Previous candle is bearish (red)
        2. Current candle is bullish (green)
        3. Current candle's body completely engulfs previous candle's body
        """
        # Previous candle must be bearish
        if previous['close'] >= previous['open']:
            return False
            
        # Current candle must be bullish
        if current['close'] <= current['open']:
            return False
            
        # Current candle must engulf previous candle
        current_body_size = self._calculate_body_size(current['open'], current['close'])
        previous_body_size = self._calculate_body_size(previous['open'], previous['close'])
        
        # Check engulfing conditions
        engulfs_bottom = current['open'] <= previous['close']
        engulfs_top = current['close'] >= previous['open']
        size_ratio = current_body_size / previous_body_size if previous_body_size > 0 else 0
        
        return engulfs_bottom and engulfs_top and size_ratio >= self.min_engulfing_ratio
    
    def _is_bearish_engulfing(self, current: dict, previous: dict) -> bool:
        """
        Check if current candle forms a bearish engulfing pattern
        
        Conditions:
        1. Previous candle is bullish (green)
        2. Current candle is bearish (red)
        3. Current candle's body completely engulfs previous candle's body
        """
        # Previous candle must be bullish
        if previous['close'] <= previous['open']:
            return False
            
        # Current candle must be bearish
        if current['close'] >= current['open']:
            return False
            
        # Current candle must engulf previous candle
        current_body_size = self._calculate_body_size(current['open'], current['close'])
        previous_body_size = self._calculate_body_size(previous['open'], previous['close'])
        
        # Check engulfing conditions
        engulfs_bottom = current['open'] >= previous['close']
        engulfs_top = current['close'] <= previous['open']
        size_ratio = current_body_size / previous_body_size if previous_body_size > 0 else 0
        
        return engulfs_bottom and engulfs_top and size_ratio >= self.min_engulfing_ratio
    
    def _calculate_volume_ratio(self, data: pd.DataFrame, index: int) -> float:
        """Calculate volume ratio compared to average volume"""
        if index < self.volume_lookback:
            avg_volume = data['volume'][:index].mean()
        else:
            avg_volume = data['volume'][index-self.volume_lookback:index].mean()
        
        if avg_volume == 0:
            return 0
            
        return data['volume'].iloc[index] / avg_volume
    
    def _calculate_signal_strength(self, current: dict, previous: dict, volume_ratio: float) -> float:
        """
        Calculate the strength of the engulfing signal
        
        Strength is based on:
        1. Volume ratio (higher volume = stronger signal)
        2. Size of engulfment (larger engulfment = stronger signal)
        3. Body ratio (larger bodies = stronger signal)
        """
        current_body = self._calculate_body_size(current['open'], current['close'])
        previous_body = self._calculate_body_size(previous['open'], previous['close'])
        
        # Size ratio component
        size_ratio = current_body / previous_body if previous_body > 0 else 1
        
        # Volume component (normalize to 0-1 scale)
        volume_component = min(volume_ratio / (self.volume_threshold * 2), 1.0)
        
        # Size component (normalize to 0-1 scale)
        size_component = min((size_ratio - 1) / 2, 1.0)
        
        # Combine components (weighted average)
        strength = (volume_component * 0.6) + (size_component * 0.4)
        
        return min(strength, 1.0)
    
    def detect_signals(self, data: pd.DataFrame) -> List[EngulfingSignal]:
        """
        Detect engulfing signals in the provided data
        
        Args:
            data: DataFrame with columns ['open', 'high', 'low', 'close', 'volume']
            
        Returns:
            List of EngulfingSignal objects
        """
        required_columns = ['open', 'high', 'low', 'close', 'volume']
        if not all(col in data.columns for col in required_columns):
            raise ValueError(f"Data must contain columns: {required_columns}")
        
        signals = []
        
        for i in range(1, len(data)):
            current = {
                'open': data['open'].iloc[i],
                'high': data['high'].iloc[i],
                'low': data['low'].iloc[i],
                'close': data['close'].iloc[i],
                'volume': data['volume'].iloc[i]
            }
            
            previous = {
                'open': data['open'].iloc[i-1],
                'high': data['high'].iloc[i-1],
                'low': data['low'].iloc[i-1],
                'close': data['close'].iloc[i-1],
                'volume': data['volume'].iloc[i-1]
            }
            
            # Check if both candles are valid
            if not (self._is_valid_candle(current) and self._is_valid_candle(previous)):
                continue
            
            # Calculate volume ratio
            volume_ratio = self._calculate_volume_ratio(data, i)
            
            # Check volume threshold
            if volume_ratio < self.volume_threshold:
                continue
            
            # Check for engulfing patterns
            engulfing_type = EngulfingType.NONE
            
            if self._is_bullish_engulfing(current, previous):
                engulfing_type = EngulfingType.BULLISH
            elif self._is_bearish_engulfing(current, previous):
                engulfing_type = EngulfingType.BEARISH
            
            if engulfing_type != EngulfingType.NONE:
                strength = self._calculate_signal_strength(current, previous, volume_ratio)
                
                signal = EngulfingSignal(
                    index=i,
                    type=engulfing_type,
                    volume_ratio=volume_ratio,
                    strength=strength,
                    current_candle=current,
                    previous_candle=previous
                )
                
                signals.append(signal)
        
        return signals
    
    def add_signals_to_dataframe(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Add signal columns to the dataframe
        
        Returns:
            DataFrame with additional columns:
            - 'engulfing_signal': 1 for bullish, -1 for bearish, 0 for none
            - 'signal_strength': strength of the signal (0-1)
            - 'volume_ratio': volume ratio compared to average
        """
        data_copy = data.copy()
        
        # Initialize new columns
        data_copy['engulfing_signal'] = 0
        data_copy['signal_strength'] = 0.0
        data_copy['volume_ratio'] = 0.0
        
        signals = self.detect_signals(data)
        
        for signal in signals:
            data_copy.loc[signal.index, 'engulfing_signal'] = (
                1 if signal.type == EngulfingType.BULLISH else -1
            )
            data_copy.loc[signal.index, 'signal_strength'] = signal.strength
            data_copy.loc[signal.index, 'volume_ratio'] = signal.volume_ratio
        
        return data_copy
    
    def plot_signals(self, data: pd.DataFrame, start_idx: int = 0, end_idx: Optional[int] = None, 
                     figsize: Tuple[int, int] = (15, 10)) -> plt.Figure:
        """
        Plot candlestick chart with engulfing signals and volume
        
        Args:
            data: DataFrame with OHLCV data
            start_idx: Start index for plotting
            end_idx: End index for plotting (None for all data)
            figsize: Figure size tuple
            
        Returns:
            Matplotlib figure object
        """
        if end_idx is None:
            end_idx = len(data)
        
        plot_data = data.iloc[start_idx:end_idx].copy()
        signals = self.detect_signals(plot_data)
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, height_ratios=[3, 1], sharex=True)
        
        # Plot candlesticks
        for i in range(len(plot_data)):
            row = plot_data.iloc[i]
            color = 'green' if row['close'] > row['open'] else 'red'
            
            # Draw the high-low line
            ax1.plot([i, i], [row['low'], row['high']], color='black', linewidth=1)
            
            # Draw the body
            body_height = abs(row['close'] - row['open'])
            body_bottom = min(row['open'], row['close'])
            
            rect = plt.Rectangle((i-0.3, body_bottom), 0.6, body_height, 
                               facecolor=color, alpha=0.7, edgecolor='black')
            ax1.add_patch(rect)
        
        # Mark engulfing signals
        for signal in signals:
            if signal.index - start_idx >= 0 and signal.index - start_idx < len(plot_data):
                plot_idx = signal.index - start_idx
                row = plot_data.iloc[plot_idx]
                
                if signal.type == EngulfingType.BULLISH:
                    ax1.scatter(plot_idx, row['low'] - (row['high'] - row['low']) * 0.1, 
                              marker='^', color='green', s=100, zorder=5)
                    ax1.annotate(f'Bull\nStr:{signal.strength:.2f}\nVol:{signal.volume_ratio:.1f}x', 
                               xy=(plot_idx, row['low']), xytext=(5, -20),
                               textcoords='offset points', fontsize=8, 
                               bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgreen', alpha=0.7))
                else:
                    ax1.scatter(plot_idx, row['high'] + (row['high'] - row['low']) * 0.1, 
                              marker='v', color='red', s=100, zorder=5)
                    ax1.annotate(f'Bear\nStr:{signal.strength:.2f}\nVol:{signal.volume_ratio:.1f}x', 
                               xy=(plot_idx, row['high']), xytext=(5, 20),
                               textcoords='offset points', fontsize=8,
                               bbox=dict(boxstyle='round,pad=0.3', facecolor='lightcoral', alpha=0.7))
        
        ax1.set_ylabel('Price')
        ax1.set_title('Volume Engulfing Indicator - Price Chart')
        ax1.grid(True, alpha=0.3)
        
        # Plot volume
        ax2.bar(range(len(plot_data)), plot_data['volume'], alpha=0.7, color='blue')
        
        # Highlight volume for signals
        for signal in signals:
            if signal.index - start_idx >= 0 and signal.index - start_idx < len(plot_data):
                plot_idx = signal.index - start_idx
                color = 'green' if signal.type == EngulfingType.BULLISH else 'red'
                ax2.bar(plot_idx, plot_data['volume'].iloc[plot_idx], alpha=0.9, color=color)
        
        ax2.set_ylabel('Volume')
        ax2.set_xlabel('Time Period')
        ax2.set_title('Volume')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig


def create_sample_data(n_periods: int = 100, seed: int = 42) -> pd.DataFrame:
    """
    Create sample OHLCV data for testing the indicator
    
    Args:
        n_periods: Number of periods to generate
        seed: Random seed for reproducibility
        
    Returns:
        DataFrame with OHLCV data
    """
    np.random.seed(seed)
    
    # Generate base price movement
    price_changes = np.random.normal(0, 0.02, n_periods)
    
    # Add some engulfing patterns if there are enough periods
    if n_periods >= 25:
        price_changes[20:25] = [0.05, 0.08, -0.06, -0.09, 0.07]  # Add some engulfing patterns
    if n_periods >= 65:
        price_changes[60:65] = [-0.04, -0.07, 0.05, 0.08, -0.03]  # Add more patterns
    
    base_price = 100
    prices = [base_price]
    
    for change in price_changes:
        prices.append(prices[-1] * (1 + change))
    
    data = []
    for i in range(n_periods):
        open_price = prices[i]
        close_price = prices[i + 1]
        
        # Generate high and low
        high_low_range = abs(close_price - open_price) * np.random.uniform(1.5, 3.0)
        high = max(open_price, close_price) + high_low_range * np.random.uniform(0, 0.5)
        low = min(open_price, close_price) - high_low_range * np.random.uniform(0, 0.5)
        
        # Generate volume (higher volume around price movements)
        base_volume = 10000
        volume_multiplier = 1 + abs(price_changes[i]) * 10
        if i in [22, 23, 62, 63]:  # Boost volume for engulfing patterns
            volume_multiplier *= 2.5
        volume = int(base_volume * volume_multiplier * np.random.uniform(0.5, 1.5))
        
        data.append({
            'open': open_price,
            'high': high,
            'low': low,
            'close': close_price,
            'volume': volume
        })
    
    return pd.DataFrame(data)


if __name__ == "__main__":
    # Example usage
    print("Volume Engulfing Indicator - Example Usage")
    print("=" * 50)
    
    # Create sample data
    sample_data = create_sample_data(100)
    
    # Initialize indicator
    indicator = VolumeEngulfingIndicator(
        volume_threshold=1.5,
        volume_lookback=20,
        min_body_ratio=0.3,
        min_engulfing_ratio=1.1
    )
    
    # Detect signals
    signals = indicator.detect_signals(sample_data)
    
    print(f"Found {len(signals)} engulfing signals:")
    print()
    
    for i, signal in enumerate(signals, 1):
        print(f"Signal {i}:")
        print(f"  Index: {signal.index}")
        print(f"  Type: {signal.type.value}")
        print(f"  Volume Ratio: {signal.volume_ratio:.2f}x")
        print(f"  Strength: {signal.strength:.2f}")
        print(f"  Current Candle - Open: {signal.current_candle['open']:.2f}, Close: {signal.current_candle['close']:.2f}")
        print(f"  Previous Candle - Open: {signal.previous_candle['open']:.2f}, Close: {signal.previous_candle['close']:.2f}")
        print()
    
    # Add signals to dataframe
    data_with_signals = indicator.add_signals_to_dataframe(sample_data)
    
    print("Sample of data with signals:")
    print(data_with_signals[data_with_signals['engulfing_signal'] != 0][['open', 'close', 'volume', 'engulfing_signal', 'signal_strength', 'volume_ratio']].head())