import yaml
from pathlib import Path

def define_env(env):
    """
    Define macros, variables, and filters for MkDocs
    """
    
    # Load examples data
    data_file = Path(__file__).parent / 'data' / 'examples.yml'
    
    print(Path(__file__).parent)
    print(f"Loading examples data from: {data_file}")

    with open(data_file, 'r') as f:
        data = yaml.safe_load(f)
        env.variables['examples'] = data['examples']
    
    @env.macro
    def example_comparison_table():
        """Generate the example comparison table"""
        examples = env.variables['examples']
        
        # Build header
        headers = ['Feature'] + [ex['name'] for ex in examples]
        header_row = '| ' + ' | '.join(headers) + ' |'
        separator = '|' + '|'.join(['---' for _ in headers]) + '|'
        
        # Build rows
        rows = []
        
        # Primary Focus row
        focus_row = ['**Primary Focus**'] + [ex['focus'] for ex in examples]
        rows.append('| ' + ' | '.join(focus_row) + ' |')
        
        # Stages row
        stages_row = ['**Stages**'] + [str(ex['stages']) for ex in examples]
        rows.append('| ' + ' | '.join(stages_row) + ' |')
        
        # Difficulty row
        diff_row = ['**Difficulty**'] + [ex['difficulty'] for ex in examples]
        rows.append('| ' + ' | '.join(diff_row) + ' |')
        
        # Compliance row
        comp_row = ['**Compliance**'] + [ex['compliance'] for ex in examples]
        rows.append('| ' + ' | '.join(comp_row) + ' |')
        
        # Encryption row
        enc_row = ['**Encryption**'] + [ex['encryption'] for ex in examples]
        rows.append('| ' + ' | '.join(enc_row) + ' |')
        
        # AI Integration row
        ai_row = ['**AI Integration**'] + [
            f"✅ Stage {ex['ai_stage']}" if ex['ai_integration'] 
            else '❌' for ex in examples
        ]
        rows.append('| ' + ' | '.join(ai_row) + ' |')
        
        # Multi-Agent row
        ma_row = ['**Multi-Agent**'] + [
            '✅' if ex['multi_agent'] else '❌' for ex in examples
        ]
        rows.append('| ' + ' | '.join(ma_row) + ' |')
        
        # Attack Types row
        attack_row = ['**Attack Types**'] + [ex['attack_types'] for ex in examples]
        rows.append('| ' + ' | '.join(attack_row) + ' |')
        
        # Defense Focus row
        defense_row = ['**Defense Focus**'] + [ex['defense_focus'] for ex in examples]
        rows.append('| ' + ' | '.join(defense_row) + ' |')
        
        # Total Hours row
        hours_row = ['**Total Hours**'] + [
            f"{ex['hours_min']}-{ex['hours_max']}" for ex in examples
        ]
        rows.append('| ' + ' | '.join(hours_row) + ' |')
        
        # Combine all
        return '\n'.join([header_row, separator] + rows)
    
    @env.macro
    def example_list_bullets():
        """Generate a bullet list of examples"""
        examples = env.variables['examples']
        bullets = []
        for ex in examples:
            bullets.append(f"- **[{ex['name']}]({ex['path']})** - {ex['focus']}")
        return '\n'.join(bullets)
    
    @env.macro
    def example_count():
        """Return the number of examples"""
        return len(env.variables['examples'])
    
    @env.macro
    def total_study_hours():
        """Calculate total study hours"""
        examples = env.variables['examples']
        min_hours = sum(ex['hours_min'] for ex in examples)
        max_hours = sum(ex['hours_max'] for ex in examples)
        return f"{min_hours}-{max_hours}"
    
    @env.macro
    def example_quick_nav():
        """Generate quick navigation links"""
        examples = env.variables['examples']
        links = []
        for ex in examples:
            emoji = "💻"
            if ex['id'] == 'adversarial':
                emoji = "🛡️"
            links.append(f"- {emoji} [{ex['name']}]({ex['path']})")
        return '\n'.join(links)