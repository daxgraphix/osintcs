/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { List } from 'react-window';

export interface VirtualizedListProps<T> {
  items: T[];
  itemHeight: number;
  height: number;
  renderItem: (item: T, index: number) => React.ReactNode;
  overscanCount?: number;
  className?: string;
}

export function VirtualizedList<T>({
  items,
  itemHeight,
  height,
  renderItem,
  overscanCount = 5,
  className,
}: VirtualizedListProps<T>) {
  if (items.length === 0) {
    return null;
  }

  const Row = ({ index, style }: { index: number; style: React.CSSProperties }) => (
    <div style={style}>
      {renderItem(items[index], index)}
    </div>
  );

  return (
    <List
      className={className}
      defaultHeight={height}
      rowCount={items.length}
      rowHeight={itemHeight}
      overscanCount={overscanCount}
      rowComponent={Row}
      rowProps={{} as any}
    />
  );
}
