import React from 'react';

export default class LearnErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error('[Learn] Component error:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: '40px', textAlign: 'center',
          background: '#161b22', borderRadius: '8px',
          border: '1px solid #f85149'
        }}>
          <div style={{ fontSize: '24px', marginBottom: '12px' }}>⚠️</div>
          <div style={{ color: '#f85149', fontSize: '16px', marginBottom: '8px' }}>
            Something went wrong rendering this section
          </div>
          <div style={{
            color: '#8b949e', fontSize: '12px',
            fontFamily: 'monospace', marginBottom: '16px'
          }}>
            {this.state.error?.message}
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              background: '#21262d', border: '1px solid #30363d',
              color: '#c9d1d9', padding: '8px 16px',
              borderRadius: '6px', cursor: 'pointer'
            }}
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
